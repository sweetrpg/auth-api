package main

import (
	"log"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/grafana/pyroscope-go"
	"github.com/joho/godotenv"
	"github.com/penglongli/gin-metrics/ginmetrics"
	sloggin "github.com/samber/slog-gin"
	actuator "github.com/sinhashubham95/go-actuator"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	apiconstants "github.com/sweetrpg/api-core.go/constants"
	"github.com/sweetrpg/api-core.go/tracing"
	"github.com/sweetrpg/api-core.go/vo"
	"github.com/sweetrpg/auth-api/auth0"
	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/auth-api/docs"
	"github.com/sweetrpg/auth-api/server"
	"github.com/sweetrpg/common.go/logging"
	"github.com/sweetrpg/common.go/util"
	"github.com/sweetrpg/mongodb.go/database"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"golang.org/x/time/rate"
)

// @title Auth API service
// @version 1.0
// @description Swagger APIs
// @termsOfService https://pilgrimagesoftware.com/terms/
// @contact.name API Support
// @contact.url https://sweetrpg.com
// @contact.email admin@sweetrpg.com
// @license.name MIT
// @license.url https://mit-license.org/
func main() {
	_ = godotenv.Load(".env")

	logging.Init()

	setupSentry()

	if stopProfiling := setupProfiling(); stopProfiling != nil {
		defer stopProfiling()
	}

	auth0Config, err := auth0.ConfigFromEnvironment()
	if err != nil {
		// Every route this service exposes depends on Auth0 verification either
		// directly (/authz/check) or as its bearer-token fallback
		// (/api/admin/*), so a missing config is a startup failure, not a
		// degraded mode to run in.
		log.Fatalf("auth-api cannot start: %v", err)
	}
	jwksCache := auth0.NewJWKSCache()

	httpLogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	r := gin.New()
	r.Use(sloggin.New(httpLogger))
	r.Use(gin.Recovery())

	setupTracing(r)
	defer tracing.TeardownTracing()

	setupCORS(r)

	checkInternalServiceTokenConfig()

	setupMetrics(r)

	database.SetupDatabase()
	defer database.TeardownDatabase()

	setupAcuator(r)

	setupSwagger(r)

	r.Use(RateLimiter())

	server.SetupHandlers(r, jwksCache, auth0Config)

	_ = r.Run(util.GetEnv(apiconstants.BIND_ADDRESS, ":8000"))
}

func setupSwagger(r *gin.Engine) {
	logging.Logger.Info("Setting up Swagger...")

	docs.SwaggerInfo.Version = os.Getenv(apiconstants.VERSION)
	docs.SwaggerInfo.Host = util.GetEnv(apiconstants.INGRESS_HOST, "localhost")
	docs.SwaggerInfo.BasePath = util.GetEnv(apiconstants.INGRESS_BASE_PATH, "/")
	docs.SwaggerInfo.Schemes = strings.Split(util.GetEnv(apiconstants.INGRESS_SCHEMES, "http"), ",")
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
}

// checkInternalServiceTokenConfig warns at startup if INTERNAL_SERVICE_TOKEN
// is unset, since that permanently disables the internal-service-token path
// on /api/admin/* (every such request falls through to the Auth0
// bearer-token check) rather than silently trusting an empty token.
func checkInternalServiceTokenConfig() {
	if util.GetEnv(constants.INTERNAL_SERVICE_TOKEN, "") == "" {
		logging.Logger.Warn("INTERNAL_SERVICE_TOKEN not set, /api/admin/* will only accept Auth0 bearer tokens with the admin role")
	}
}

func setupCORS(r *gin.Engine) {
	logging.Logger.Info("Setting up CORS...")

	origins := util.GetEnv(constants.ALLOWED_ORIGINS, "")
	if origins == "" {
		logging.Logger.Warn("ALLOWED_ORIGINS not set, no cross-origin requests will be allowed")
		return
	}

	r.Use(cors.New(cors.Config{
		AllowOrigins:     strings.Split(origins, ","),
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
}

func setupSentry() {
	logging.Logger.Info("Setting up Sentry...")

	sentryDsn, found := os.LookupEnv(apiconstants.SENTRY_DSN)
	if found {
		sentryDebug, _ := strconv.ParseBool(util.GetEnv(apiconstants.SENTRY_DEBUG, "false"))
		err := sentry.Init(sentry.ClientOptions{
			Dsn:              sentryDsn,
			Debug:            sentryDebug,
			AttachStacktrace: true,
			EnableTracing:    true,
			TracesSampleRate: 1.0,
			TracesSampler: sentry.TracesSampler(func(ctx sentry.SamplingContext) float64 {
				if strings.Contains(ctx.Span.Name, "/status/") {
					return 0.0
				}
				return 1.0
			}),
			ServerName: constants.ServiceName,
		})
		if err != nil {
			logging.Logger.Error("Error while trying to initialize Sentry", "error", err.Error())
		}
		defer func() {
			log.Print("Flushing Sentry...")
			sentry.Flush(2 * time.Second)
		}()
	}
}

func setupProfiling() func() {
	logging.Logger.Info("Setting up continuous profiling...")

	serverAddress, found := os.LookupEnv(constants.PYROSCOPE_SERVER_ADDRESS)
	if !found {
		logging.Logger.Warn("PYROSCOPE_SERVER_ADDRESS not set, continuous profiling disabled")
		return nil
	}

	profiler, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: constants.ServiceName,
		ServerAddress:   serverAddress,
		TenantID:        util.GetEnv(constants.PYROSCOPE_TENANT_ID, ""),
		Tags: map[string]string{
			"env": util.GetEnv(apiconstants.ENV, "dev"),
		},
	})
	if err != nil {
		logging.Logger.Error("Error while trying to initialize continuous profiling", "error", err.Error())
		return nil
	}

	return func() {
		_ = profiler.Stop()
	}
}

func setupAcuator(r *gin.Engine) {
	logging.Logger.Info("Setting up actuator...")

	actuatorHandler := actuator.GetActuatorHandler(&actuator.Config{
		Endpoints: []int{
			actuator.Env,
			actuator.Info,
			actuator.Metrics,
			actuator.Ping,
			actuator.ThreadDump,
		},
		Env:     util.GetEnv(apiconstants.ENV, "dev"),
		Name:    constants.ServiceName,
		Port:    util.GetEnvInt(apiconstants.PORT, 0),
		Version: util.GetEnv(apiconstants.VERSION, "v0.0.0"),
	})
	ginActuatorHandler := func(ctx *gin.Context) {
		actuatorHandler(ctx.Writer, ctx.Request)
	}
	r.GET("/actuator/*endpoint", ginActuatorHandler)
}

func setupTracing(r *gin.Engine) {
	logging.Logger.Info("Setting up tracing...")

	// Teardown is deferred by the caller (main), not here - deferring it in this function
	// would run it as soon as this function returns, shutting down the tracer provider
	// before the server ever serves a request, silently dropping every span.
	tracing.SetupTracing(constants.ServiceName)
	r.Use(otelgin.Middleware(constants.ServiceName))
}

func setupMetrics(r *gin.Engine) {
	logging.Logger.Info("Setting up metrics endpoint...")

	m := ginmetrics.GetMonitor()
	m.SetMetricPath("/metrics")
	m.SetSlowTime(10)
	m.SetDuration([]float64{0.1, 0.3, 1.2, 5, 10})
	m.Use(r)
}

func RateLimiter() gin.HandlerFunc {
	limiter := rate.NewLimiter(1, util.GetEnvInt(apiconstants.RATE_LIMIT, 10))

	return func(c *gin.Context) {
		if limiter.Allow() {
			c.Next()
		} else {
			logging.Logger.Warn("Rate limit exceeded")
			c.JSON(429, vo.ErrorVO{
				Error:   apiconstants.ErrorRateLimited,
				Message: "Limit exceeded",
			})
		}
	}
}

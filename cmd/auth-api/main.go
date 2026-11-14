package main

import (
	"context"
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
	"github.com/sweetrpg/api-core.go/featureflags"
	"github.com/sweetrpg/api-core.go/ratelimit"
	"github.com/sweetrpg/api-core.go/tracing"
	apiutil "github.com/sweetrpg/api-core.go/util"
	"github.com/sweetrpg/auth-api/auth0"
	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/auth-api/docs"
	"github.com/sweetrpg/auth-api/events"
	"github.com/sweetrpg/auth-api/fga"
	"github.com/sweetrpg/auth-api/models"
	"github.com/sweetrpg/auth-api/server"
	"github.com/sweetrpg/common.go/logging"
	"github.com/sweetrpg/common.go/util"
	"github.com/sweetrpg/mongodb.go/database"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
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

	ff := featureflags.New(constants.ServiceName)

	if stopProfiling := setupProfiling(ff); stopProfiling != nil {
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

	setupMetrics(r)

	database.SetupDatabase()
	defer database.TeardownDatabase()

	setupAcuator(r)

	setupSwagger(r)

	// Per-client/IP rate limiter (Redis-backed, fail-closed). Tier values come from the env
	// (RATE_LIMIT_*); auth-api runs a looser posture so the synchronous catalog-api -> /authz/check
	// chain is not throttled. A rate-limit-store outage returns 503, never unlimited traffic.
	redisPool := apiutil.RedisPool()
	if redisPool != nil {
		pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := ratelimit.Ping(pingCtx, redisPool); err != nil {
			logging.Logger.Error("REDIS_HOST is configured but unreachable at startup; rate-limited requests will fail closed until it recovers",
				"error", err.Error())
		}
		cancel()
	} else {
		logging.Logger.Warn("REDIS_HOST is not configured; rate limiting will fail closed (503) on every limited request")
	}
	r.Use(ratelimit.Middleware(redisPool, ratelimit.DefaultOptions()))

	if natsURL := os.Getenv("NATS_URL"); natsURL == "" {
		logging.Logger.Warn("NATS_URL is not set; deny and role-removal events are not published")
	} else {
		bus, err := events.ConnectNATS(natsURL)
		if err != nil {
			log.Fatalf("auth-api cannot start: %v", err)
		}
		defer bus.Close()
		server.SetEventEmitter(events.NewEmitter(bus, events.DefaultBackoff))
	}

	server.SetupHandlers(r, jwksCache, auth0Config)
	fgaStore := setupFGAStore()
	server.SetupFGAHandlers(r, jwksCache, auth0Config, fgaStore)
	sessionLimits := server.SessionLimitsFromEnv()
	var sessionLimiter *ratelimit.Limiter
	if redisPool != nil {
		sessionLimiter = ratelimit.New(redisPool, server.SessionTiers(sessionLimits))
	}
	setupSessionEndpoints(r, jwksCache, auth0Config, fgaStore, sessionLimiter, sessionLimits)

	_ = r.Run(util.GetEnv(apiconstants.BIND_ADDRESS, ":8000"))
}

// setupSessionEndpoints registers the PADR-0040 session endpoints. With no Redis pool the limiter is
// nil and every session request answers 503 rather than run unlimited.
func setupSessionEndpoints(r *gin.Engine, cache *auth0.JWKSCache, cfg auth0.Config, store fga.Store, limiter *ratelimit.Limiter, limits server.SessionLimits) {
	if err := models.EnsureSessionMintIndexes(context.Background()); err != nil {
		logging.Logger.Error("Could not create session mint indexes", "error", err.Error())
		os.Exit(1)
	}
	server.SetupSessionHandlers(r, cache, cfg, store, models.MintStore{}, limiter, limits)
}

// setupFGAStore bootstraps the OpenFGA store and model and returns the client. A misconfigured or
// unreachable OpenFGA fails startup, so the pod restarts rather than serving checks it cannot make.
func setupFGAStore() fga.Store {
	cfg, err := fga.ConfigFromEnvironment()
	if err != nil {
		logging.Logger.Error("OpenFGA configuration invalid", "error", err.Error())
		os.Exit(1)
	}
	boot, err := fga.Bootstrap(context.Background(), cfg.APIURL, cfg.StoreName, cfg.APIKey)
	if err != nil {
		logging.Logger.Error("OpenFGA bootstrap failed", "error", err.Error())
		os.Exit(1)
	}
	client, err := fga.NewClient(cfg.APIURL, boot.StoreID, boot.ModelID, cfg.APIKey)
	if err != nil {
		logging.Logger.Error("OpenFGA client setup failed", "error", err.Error())
		os.Exit(1)
	}
	return client
}

func setupSwagger(r *gin.Engine) {
	logging.Logger.Info("Setting up Swagger...")

	docs.SwaggerInfo.Version = os.Getenv(apiconstants.VERSION)
	docs.SwaggerInfo.Host = util.GetEnv(apiconstants.INGRESS_HOST, "localhost")
	docs.SwaggerInfo.BasePath = util.GetEnv(apiconstants.INGRESS_BASE_PATH, "/")
	docs.SwaggerInfo.Schemes = strings.Split(util.GetEnv(apiconstants.INGRESS_SCHEMES, "http"), ",")
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
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

// setupProfiling starts continuous profiling only when the profiling-enabled
// feature flag evaluates to true, regardless of whether
// PYROSCOPE_SERVER_ADDRESS happens to be set - the flag is the on/off
// control, PYROSCOPE_SERVER_ADDRESS is only the destination. See the
// pyroscope-profiling-flag spec's three scenarios.
func setupProfiling(ff *featureflags.Client) func() {
	logging.Logger.Info("Setting up continuous profiling...")

	if !ff.BoolFlag(context.Background(), constants.ProfilingEnabledFlag, false) {
		logging.Logger.Info("profiling-enabled flag is off, continuous profiling disabled")
		return nil
	}

	serverAddress, found := os.LookupEnv(constants.PYROSCOPE_SERVER_ADDRESS)
	if !found {
		logging.Logger.Warn("profiling-enabled flag is on but PYROSCOPE_SERVER_ADDRESS not set, continuous profiling disabled")
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

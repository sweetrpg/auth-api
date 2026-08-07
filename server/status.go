package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	apicores "github.com/sweetrpg/api-core.go/server"
	_ "github.com/sweetrpg/api-core.go/vo"
	"github.com/sweetrpg/common.go/logging"
)

func setupStatusHandlers(g *gin.Engine) {
	logging.Logger.Info("Setting up status endpoint handlers...")

	{
		a := g.Group("/status")
		a.GET("/health", healthHandler)
	}

	g.GET("/status/ping", pingHandler)
}

// Health check.
//
//	 Do a health check of the application and its dependencies and return the results
//		@Summary		Health check
//		@Description	Health check
//		@Tags			status
//		@Produce		json
//		@Success		200		{object}	vo.HealthResponseVO
//		@Router			/status/health [get]
func healthHandler(c *gin.Context) {
	resp := apicores.HealthHandler(c.Request.Context())
	status := http.StatusOK
	if resp.Errors > 0 {
		status = http.StatusServiceUnavailable
	}
	c.JSON(status, resp)
}

// Ping the application.
//
//	 A shallow health check to see if basic responses are working. Returns the date and hostname of the server handling the request.
//		@Summary		Ping
//		@Description	Ping
//		@Tags			status
//		@Produce		json
//		@Success		200		{object}	vo.PingResponseVO
//		@Router			/status/ping [get]
func pingHandler(c *gin.Context) {
	c.JSON(http.StatusOK, apicores.PingHandler())
}

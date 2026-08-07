package server

import (
	"github.com/gin-gonic/gin"
	"github.com/sweetrpg/auth-api/auth0"
)

func SetupHandlers(g *gin.Engine, cache *auth0.JWKSCache, config auth0.Config) {
	setupAuthzHandlers(g, cache, config)
	setupRolesHandlers(g, cache, config)
	setupStatusHandlers(g)
}

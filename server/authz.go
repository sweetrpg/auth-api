package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sweetrpg/auth-api/auth0"
	"github.com/sweetrpg/auth-api/models"
	"github.com/sweetrpg/common.go/logging"
)

type authzCheckRequest struct {
	Service string `json:"service" binding:"required"`
	Action  string `json:"action"`
}

type authzAllowedResponse struct {
	Allowed bool     `json:"allowed"`
	Roles   []string `json:"roles"`
	Sub     string   `json:"sub"`
}

type authzDeniedResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type authzErrorResponse struct {
	Error string `json:"error"`
}

func setupAuthzHandlers(g *gin.Engine, cache *auth0.JWKSCache, config auth0.Config) {
	logging.Logger.Info("Setting up authz endpoint handlers...")

	g.POST("/authz/check", func(c *gin.Context) { checkAuthz(c, cache, config) })
}

// Check whether a subject may access a service.
//
//	 Verifies the bearer token against Auth0's JWKS, then looks up the subject's roles and any deny entry for the requested service.
//		@Summary		Authorize a service request
//		@Description	Authorize a service request
//		@Tags			authz
//		@Accept			json
//		@Produce		json
//		@Param			Authorization	header		string				true	"Bearer <Auth0 access token>"
//		@Param			request			body		authzCheckRequest	true	"Service to check access for"
//		@Success		200				{object}	authzAllowedResponse
//		@Success		200				{object}	authzDeniedResponse
//		@Failure		401				{object}	authzErrorResponse
//		@Router			/authz/check [post]
func checkAuthz(c *gin.Context, cache *auth0.JWKSCache, config auth0.Config) {
	var req authzCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		invalidTokenResponse(c)
		return
	}

	token := bearerToken(c)
	if token == "" {
		invalidTokenResponse(c)
		return
	}

	claims, err := cache.Verify(c.Request.Context(), token, config)
	if err != nil {
		// Logged at Warn, not Error: an invalid/expired token is a routine client condition,
		// not a service fault. Still logs the real reason (bad signature, expired, wrong
		// issuer/audience, unresolvable kid) so it stays distinguishable from a downstream
		// dependency failure below - the Swift service's equivalent check collapsed both into
		// one generic "invalid_token" response with no logged cause, which cost real debugging
		// time during a MongoDB decode failure that looked identical to an invalid token.
		logging.Logger.Warn("Token verification failed", "error", err.Error())
		invalidTokenResponse(c)
		return
	}

	subject := claims.Subject

	denied, err := models.HasDenyEntry(c.Request.Context(), subject, req.Service)
	if err != nil {
		logging.Logger.Error("Failed to look up deny entry", "error", err.Error())
		c.JSON(http.StatusInternalServerError, authzErrorResponse{Error: "query_failed"})
		return
	}
	if denied {
		c.JSON(http.StatusOK, authzDeniedResponse{Allowed: false, Reason: "service_denied"})
		return
	}

	roles, err := models.ListRolesForSubject(c.Request.Context(), subject)
	if err != nil {
		logging.Logger.Error("Failed to look up roles", "error", err.Error())
		c.JSON(http.StatusInternalServerError, authzErrorResponse{Error: "query_failed"})
		return
	}

	roleNames := make([]string, 0, len(roles))
	for _, r := range roles {
		roleNames = append(roleNames, string(r.Role))
	}
	if len(roleNames) == 0 {
		roleNames = []string{string(models.RoleUser)}
	}

	c.JSON(http.StatusOK, authzAllowedResponse{Allowed: true, Roles: roleNames, Sub: subject})
}

func invalidTokenResponse(c *gin.Context) {
	c.JSON(http.StatusUnauthorized, authzErrorResponse{Error: "invalid_token"})
}

func bearerToken(c *gin.Context) string {
	const prefix = "Bearer "
	auth := c.GetHeader("Authorization")
	if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
		return ""
	}
	return auth[len(prefix):]
}

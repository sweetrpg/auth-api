package server

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/sweetrpg/auth-api/auth0"
	"github.com/sweetrpg/auth-api/constants"
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
	ensureUserResolver()

	g.POST("/authz/check", func(c *gin.Context) { checkAuthz(c, cache, config) })
}

// Check whether a subject may access a service.
//
//	 Verifies the bearer token against Auth0's JWKS, then looks up the subject's roles and any deny entry for the requested service.
//	 A subject with no role rows is a user; an admin also gets user (an admin-only row would otherwise fail every user-gated API); no other role implies user.
//		@Summary		Authorize a service request
//		@Description	Authorize a service request. Roles: user when the subject has no role rows; admin implies user; no other role implies user.
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
	p := cachedPrincipal(subject)
	if req.Service != constants.USERS_API_SERVICE {
		p = ownPrincipal(c.Request.Context(), subject, token)
	}

	denied, err := models.HasDenyEntry(c.Request.Context(), p, req.Service)
	if err != nil {
		logging.Logger.Error("Failed to look up deny entry", "error", err.Error())
		c.JSON(http.StatusInternalServerError, authzErrorResponse{Error: "query_failed"})
		return
	}
	if denied {
		c.JSON(http.StatusOK, authzDeniedResponse{Allowed: false, Reason: "service_denied"})
		return
	}

	roles, err := models.ListRolesFor(c.Request.Context(), p)
	if err != nil {
		logging.Logger.Error("Failed to look up roles", "error", err.Error())
		c.JSON(http.StatusInternalServerError, authzErrorResponse{Error: "query_failed"})
		return
	}

	c.JSON(http.StatusOK, authzAllowedResponse{Allowed: true, Roles: effectiveRoles(roles), Sub: subject})
}

// effectiveRoles are the roles /authz/check returns. A subject with no rows is a plain user. An
// admin also holds user, so an account whose only row is admin is not locked out of user-gated
// APIs. No other explicit role implies user: the reconciler's openfga-writer must stay unable to
// call them (PADR-0038, PADR-0041). The admin role API stores and lists rows as they are.
func effectiveRoles(rows []*models.UserRole) []string {
	names := make([]string, 0, len(rows)+1)
	for _, r := range rows {
		names = append(names, string(r.Role))
	}
	if len(names) == 0 {
		return []string{string(models.RoleUser)}
	}
	if slices.Contains(names, string(models.RoleAdmin)) && !slices.Contains(names, string(models.RoleUser)) {
		names = append(names, string(models.RoleUser))
	}
	return names
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

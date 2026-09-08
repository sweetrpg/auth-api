package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	apiv "github.com/sweetrpg/api-core.go/vo"
	"github.com/sweetrpg/auth-api/auth0"
	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/auth-api/models"
	"github.com/sweetrpg/authz-client.go/authz"
	"github.com/sweetrpg/common.go/logging"
	"github.com/sweetrpg/common.go/util"
)

const (
	internalServiceTokenHeader = "X-Internal-Service-Token"
	actingUserSubHeader        = "X-Acting-User-Sub"
)

type subjectRolesSummary struct {
	Subject        string   `json:"subject"`
	Roles          []string `json:"roles"`
	DeniedServices []string `json:"deniedServices"`
}

type roleAssignmentRequest struct {
	Role string `json:"role" binding:"required"`
}

type denyEntryRequest struct {
	Service string `json:"service" binding:"required"`
}

// auth-api has no user list of its own to serve (no email, no profile data)
// - admin-web composes users-api's user list with the bulk lookup here
// (GET /api/admin/roles?subjects=...), joined by Auth0 subject.
func setupRolesHandlers(g *gin.Engine, cache *auth0.JWKSCache, config auth0.Config) {
	logging.Logger.Info("Setting up admin roles endpoint handlers...")

	usersBaseURL := util.GetEnv(constants.USERS_API_URL, "")
	authzClient := authz.NewClient("", usersBaseURL)

	group := g.Group("/api/admin")
	group.GET("/roles", func(c *gin.Context) { listRoles(c, cache, config) })
	group.GET("/roles/:subject", func(c *gin.Context) { getSubject(c, cache, config) })
	group.POST("/roles/:subject", func(c *gin.Context) { addRole(c, cache, config, authzClient, usersBaseURL) })
	group.DELETE("/roles/:subject/:role", func(c *gin.Context) { removeRole(c, cache, config, authzClient, usersBaseURL) })
	// Static /deny-entries/stats is registered before the /deny-entries/:subject param route so
	// "stats" is never captured as a subject.
	group.GET("/deny-entries/stats", func(c *gin.Context) { denyEntryStats(c, cache, config) })
	group.POST("/deny-entries/:subject", func(c *gin.Context) { addDenyEntry(c, cache, config, authzClient, usersBaseURL) })
	group.DELETE("/deny-entries/:subject/:service", func(c *gin.Context) { removeDenyEntry(c, cache, config, authzClient, usersBaseURL) })
}

type denyEntryStatsResponse struct {
	RestrictedUsers int `json:"restricted_users"`
}

// Count of users with at least one service restriction.
//
//	 The number of distinct subjects with one or more service deny entries, for admin-web's
//	 platform metrics page. Plain JSON, not JSON:API. Requires the internal service token, or an
//	 Auth0 bearer token with the admin role.
//		@Summary		Count of restricted users
//		@Description	Number of distinct subjects with at least one active service deny entry
//		@Tags			admin
//		@Produce		json
//		@Param			X-Internal-Service-Token	header		string	false	"Shared internal-service secret"
//		@Param			X-Acting-User-Sub			header		string	false	"Acting admin's Auth0 sub"
//		@Success		200							{object}	denyEntryStatsResponse
//		@Failure		401							{object}	apiv.ErrorVO
//		@Failure		403							{object}	apiv.ErrorVO
//		@Failure		500							{object}	apiv.ErrorVO
//		@Router			/api/admin/deny-entries/stats [get]
func denyEntryStats(c *gin.Context, cache *auth0.JWKSCache, config auth0.Config) {
	if _, _, ok := verifyAdminRole(c, cache, config); !ok {
		return
	}

	count, err := models.CountRestrictedSubjects(c.Request.Context())
	if err != nil {
		logging.Logger.Error("Failed to count restricted subjects", "error", err.Error())
		c.JSON(http.StatusInternalServerError, apiv.ErrorVO{Error: "query_failed", Message: "failed to count restricted users"})
		return
	}
	c.JSON(http.StatusOK, denyEntryStatsResponse{RestrictedUsers: count})
}

// GET /api/admin/roles?subjects=sub1,sub2,... - bulk roles/deny-entries for
// a set of subjects, in one round trip, so admin-web's user list doesn't do
// a per-row call.
//
//	 Requires the internal service token, or an Auth0 bearer token with the admin role.
//		@Summary		Bulk lookup of roles/deny-entries by subject
//		@Description	Bulk lookup of roles/deny-entries by subject
//		@Tags			admin
//		@Produce		json
//		@Param			X-Internal-Service-Token	header		string	false	"Shared internal-service secret"
//		@Param			X-Acting-User-Sub			header		string	false	"Acting admin's Auth0 sub, for audit attribution"
//		@Param			subjects					query		string	true	"Comma-separated Auth0 subjects"
//		@Success		200							{array}		subjectRolesSummary
//		@Failure		400							{object}	apiv.ErrorVO
//		@Failure		401							{object}	apiv.ErrorVO
//		@Failure		403							{object}	apiv.ErrorVO
//		@Failure		500							{object}	apiv.ErrorVO
//		@Router			/api/admin/roles [get]
func listRoles(c *gin.Context, cache *auth0.JWKSCache, config auth0.Config) {
	if _, _, ok := verifyAdminRole(c, cache, config); !ok {
		return
	}

	raw := c.Query("subjects")
	if raw == "" {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: "subjects query parameter is required"})
		return
	}

	subjects := strings.Split(raw, ",")
	summaries := make([]subjectRolesSummary, 0, len(subjects))
	for _, subject := range subjects {
		summary, err := buildSummary(c.Request.Context(), subject)
		if err != nil {
			logging.Logger.Error("Failed to build roles summary", "error", err.Error())
			c.JSON(http.StatusInternalServerError, apiv.ErrorVO{Error: "query_failed", Message: "failed to list roles"})
			return
		}
		summaries = append(summaries, summary)
	}
	c.JSON(http.StatusOK, summaries)
}

// Get a subject's roles and deny entries.
//
//	 Requires the internal service token, or an Auth0 bearer token with the admin role.
//		@Summary		Get a subject's roles and deny entries
//		@Description	Get a subject's roles and deny entries
//		@Tags			admin
//		@Produce		json
//		@Param			X-Internal-Service-Token	header		string	false	"Shared internal-service secret"
//		@Param			X-Acting-User-Sub			header		string	false	"Acting admin's Auth0 sub, for audit attribution"
//		@Param			subject						path		string	true	"Auth0 subject"
//		@Success		200							{object}	subjectRolesSummary
//		@Failure		400							{object}	apiv.ErrorVO
//		@Failure		401							{object}	apiv.ErrorVO
//		@Failure		403							{object}	apiv.ErrorVO
//		@Failure		500							{object}	apiv.ErrorVO
//		@Router			/api/admin/roles/{subject} [get]
func getSubject(c *gin.Context, cache *auth0.JWKSCache, config auth0.Config) {
	if _, _, ok := verifyAdminRole(c, cache, config); !ok {
		return
	}

	subject := c.Param("subject")
	if subject == "" {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: "invalid subject"})
		return
	}
	summary, err := buildSummary(c.Request.Context(), subject)
	if err != nil {
		logging.Logger.Error("Failed to build roles summary", "error", err.Error())
		c.JSON(http.StatusInternalServerError, apiv.ErrorVO{Error: "query_failed", Message: "failed to get subject"})
		return
	}
	c.JSON(http.StatusOK, summary)
}

func buildSummary(ctx context.Context, subject string) (subjectRolesSummary, error) {
	roles, err := models.ListRolesForSubject(ctx, subject)
	if err != nil {
		return subjectRolesSummary{}, err
	}
	denials, err := models.ListDenyEntriesForSubject(ctx, subject)
	if err != nil {
		return subjectRolesSummary{}, err
	}

	roleNames := make([]string, 0, len(roles))
	for _, r := range roles {
		roleNames = append(roleNames, string(r.Role))
	}
	if len(roleNames) == 0 {
		roleNames = []string{string(models.RoleUser)}
	}

	deniedServices := make([]string, 0, len(denials))
	for _, d := range denials {
		deniedServices = append(deniedServices, d.Service)
	}

	return subjectRolesSummary{Subject: subject, Roles: roleNames, DeniedServices: deniedServices}, nil
}

// Add a role to a subject.
//
//	 Idempotent - a no-op, not a duplicate, if the subject already holds the role. Requires the internal service token, or an Auth0 bearer token with the admin role.
//		@Summary		Add a role to a subject
//		@Description	Add a role to a subject
//		@Tags			admin
//		@Accept			json
//		@Param			X-Internal-Service-Token	header	string					false	"Shared internal-service secret"
//		@Param			X-Acting-User-Sub			header	string					false	"Acting admin's Auth0 sub, for audit attribution"
//		@Param			subject						path	string					true	"Auth0 subject"
//		@Param			request						body	roleAssignmentRequest	true	"Role to add"
//		@Success		201							"Created"
//		@Success		204							"No Content - role already present"
//		@Failure		400							{object}	apiv.ErrorVO
//		@Failure		401							{object}	apiv.ErrorVO
//		@Failure		403							{object}	apiv.ErrorVO
//		@Failure		500							{object}	apiv.ErrorVO
//		@Router			/api/admin/roles/{subject} [post]
func addRole(c *gin.Context, cache *auth0.JWKSCache, config auth0.Config, authzClient *authz.Client, usersBaseURL string) {
	actingUserSub, token, ok := verifyAdminRole(c, cache, config)
	if !ok {
		return
	}

	actingUserID, err := resolveActingUser(c.Request.Context(), authzClient, usersBaseURL, actingUserSub, token)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, apiv.ErrorVO{Error: "user_resolution_unavailable", Message: "unable to resolve the calling user"})
		return
	}

	subject := c.Param("subject")
	if subject == "" {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: "invalid subject"})
		return
	}
	var req roleAssignmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: err.Error()})
		return
	}
	role, ok := models.ParseRole(req.Role)
	if !ok {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: "invalid role"})
		return
	}

	status, err := performAudited(c.Request.Context(), actingUserID, "add_role", subject, string(role),
		func(ctx context.Context) (int, error) {
			exists, err := models.HasRole(ctx, subject, role)
			if err != nil {
				return 0, err
			}
			if exists {
				return http.StatusNoContent, nil
			}
			if err := models.AddRole(ctx, subject, role, actingUserID); err != nil {
				return 0, err
			}
			return http.StatusCreated, nil
		})
	if err != nil {
		logging.Logger.Error("Failed to add role", "error", err.Error())
		c.JSON(http.StatusInternalServerError, apiv.ErrorVO{Error: "audit_failed", Message: "failed to add role"})
		return
	}
	c.Status(status)
}

// Remove a role from a subject.
//
//	 Requires the internal service token, or an Auth0 bearer token with the admin role.
//		@Summary		Remove a role from a subject
//		@Description	Remove a role from a subject
//		@Tags			admin
//		@Param			X-Internal-Service-Token	header	string	false	"Shared internal-service secret"
//		@Param			X-Acting-User-Sub			header	string	false	"Acting admin's Auth0 sub, for audit attribution"
//		@Param			subject						path	string	true	"Auth0 subject"
//		@Param			role						path	string	true	"Role to remove"
//		@Success		204							"No Content"
//		@Failure		400							{object}	apiv.ErrorVO
//		@Failure		401							{object}	apiv.ErrorVO
//		@Failure		403							{object}	apiv.ErrorVO
//		@Failure		500							{object}	apiv.ErrorVO
//		@Router			/api/admin/roles/{subject}/{role} [delete]
func removeRole(c *gin.Context, cache *auth0.JWKSCache, config auth0.Config, authzClient *authz.Client, usersBaseURL string) {
	actingUserSub, token, ok := verifyAdminRole(c, cache, config)
	if !ok {
		return
	}

	actingUserID, err := resolveActingUser(c.Request.Context(), authzClient, usersBaseURL, actingUserSub, token)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, apiv.ErrorVO{Error: "user_resolution_unavailable", Message: "unable to resolve the calling user"})
		return
	}

	subject := c.Param("subject")
	if subject == "" {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: "invalid subject"})
		return
	}
	role, ok := models.ParseRole(c.Param("role"))
	if !ok {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: "invalid role"})
		return
	}

	status, err := performAudited(c.Request.Context(), actingUserID, "remove_role", subject, string(role),
		func(ctx context.Context) (int, error) {
			if err := models.RemoveRole(ctx, subject, role); err != nil {
				return 0, err
			}
			return http.StatusNoContent, nil
		})
	if err != nil {
		logging.Logger.Error("Failed to remove role", "error", err.Error())
		c.JSON(http.StatusInternalServerError, apiv.ErrorVO{Error: "audit_failed", Message: "failed to remove role"})
		return
	}
	c.Status(status)
}

// Add a service deny entry for a subject.
//
//	 Idempotent - a no-op, not a duplicate, if the entry already exists. Requires the internal service token, or an Auth0 bearer token with the admin role.
//		@Summary		Deny a subject access to a service
//		@Description	Deny a subject access to a service
//		@Tags			admin
//		@Accept			json
//		@Param			X-Internal-Service-Token	header	string				false	"Shared internal-service secret"
//		@Param			X-Acting-User-Sub			header	string				false	"Acting admin's Auth0 sub, for audit attribution"
//		@Param			subject						path	string				true	"Auth0 subject"
//		@Param			request						body	denyEntryRequest	true	"Service to deny"
//		@Success		201							"Created"
//		@Success		204							"No Content - deny entry already present"
//		@Failure		400							{object}	apiv.ErrorVO
//		@Failure		401							{object}	apiv.ErrorVO
//		@Failure		403							{object}	apiv.ErrorVO
//		@Failure		500							{object}	apiv.ErrorVO
//		@Router			/api/admin/deny-entries/{subject} [post]
func addDenyEntry(c *gin.Context, cache *auth0.JWKSCache, config auth0.Config, authzClient *authz.Client, usersBaseURL string) {
	actingUserSub, token, ok := verifyAdminRole(c, cache, config)
	if !ok {
		return
	}

	actingUserID, err := resolveActingUser(c.Request.Context(), authzClient, usersBaseURL, actingUserSub, token)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, apiv.ErrorVO{Error: "user_resolution_unavailable", Message: "unable to resolve the calling user"})
		return
	}

	subject := c.Param("subject")
	if subject == "" {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: "invalid subject"})
		return
	}
	var req denyEntryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: err.Error()})
		return
	}

	status, err := performAudited(c.Request.Context(), actingUserID, "add_deny_entry", subject, req.Service,
		func(ctx context.Context) (int, error) {
			exists, err := models.HasDenyEntry(ctx, subject, req.Service)
			if err != nil {
				return 0, err
			}
			if exists {
				return http.StatusNoContent, nil
			}
			if err := models.AddDenyEntry(ctx, subject, req.Service, actingUserID); err != nil {
				return 0, err
			}
			return http.StatusCreated, nil
		})
	if err != nil {
		logging.Logger.Error("Failed to add deny entry", "error", err.Error())
		c.JSON(http.StatusInternalServerError, apiv.ErrorVO{Error: "audit_failed", Message: "failed to add deny entry"})
		return
	}
	c.Status(status)
}

// Remove a service deny entry for a subject.
//
//	 Requires the internal service token, or an Auth0 bearer token with the admin role.
//		@Summary		Remove a subject's service deny entry
//		@Description	Remove a subject's service deny entry
//		@Tags			admin
//		@Param			X-Internal-Service-Token	header	string	false	"Shared internal-service secret"
//		@Param			X-Acting-User-Sub			header	string	false	"Acting admin's Auth0 sub, for audit attribution"
//		@Param			subject						path	string	true	"Auth0 subject"
//		@Param			service						path	string	true	"Service to un-deny"
//		@Success		204							"No Content"
//		@Failure		400							{object}	apiv.ErrorVO
//		@Failure		401							{object}	apiv.ErrorVO
//		@Failure		403							{object}	apiv.ErrorVO
//		@Failure		500							{object}	apiv.ErrorVO
//		@Router			/api/admin/deny-entries/{subject}/{service} [delete]
func removeDenyEntry(c *gin.Context, cache *auth0.JWKSCache, config auth0.Config, authzClient *authz.Client, usersBaseURL string) {
	actingUserSub, token, ok := verifyAdminRole(c, cache, config)
	if !ok {
		return
	}

	actingUserID, err := resolveActingUser(c.Request.Context(), authzClient, usersBaseURL, actingUserSub, token)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, apiv.ErrorVO{Error: "user_resolution_unavailable", Message: "unable to resolve the calling user"})
		return
	}

	subject := c.Param("subject")
	if subject == "" {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: "invalid subject"})
		return
	}
	service := c.Param("service")
	if service == "" {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: "invalid service"})
		return
	}

	status, err := performAudited(c.Request.Context(), actingUserID, "remove_deny_entry", subject, service,
		func(ctx context.Context) (int, error) {
			if err := models.RemoveDenyEntry(ctx, subject, service); err != nil {
				return 0, err
			}
			return http.StatusNoContent, nil
		})
	if err != nil {
		logging.Logger.Error("Failed to remove deny entry", "error", err.Error())
		c.JSON(http.StatusInternalServerError, apiv.ErrorVO{Error: "audit_failed", Message: "failed to remove deny entry"})
		return
	}
	c.Status(status)
}

// performAudited writes an AdminActionAuditLog row *before* running
// operation, and fails closed - never calling operation at all - if that
// write itself fails: an admin action that can't be logged must not be
// performed. Updates the same row to succeeded/failed after operation
// completes; that post-write is best-effort (logged on failure, but doesn't
// retroactively undo an action that already happened - the pre-write is the
// hard gate, not the post-write).
func performAudited(
	ctx context.Context, actingUserSub, action, targetSubject, detail string,
	operation func(context.Context) (int, error),
) (int, error) {
	return performAuditedWith(
		ctx, actingUserSub, action, targetSubject, detail, operation,
		models.RecordAuditAttempt, models.CompleteAudit,
	)
}

// performAuditedWith takes the audit read/write functions as parameters so
// the fail-closed contract above (operation must never run if the "before"
// audit write fails) can be verified in a test without a live database -
// see roles_audit_test.go.
func performAuditedWith(
	ctx context.Context, actingUserSub, action, targetSubject, detail string,
	operation func(context.Context) (int, error),
	recordAttempt func(context.Context, string, string, string, string) (uuid.UUID, error),
	complete func(context.Context, uuid.UUID, models.AuditStatus, string) error,
) (int, error) {
	auditID, err := recordAttempt(ctx, actingUserSub, action, targetSubject, detail)
	if err != nil {
		logging.Logger.Error("Refusing to perform admin action - audit log write failed", "action", action, "error", err.Error())
		return 0, fmt.Errorf("could not record audit log; action not performed: %w", err)
	}

	status, opErr := operation(ctx)
	if opErr != nil {
		if err := complete(ctx, auditID, models.AuditFailed, opErr.Error()); err != nil {
			logging.Logger.Warn("Failed to record failure for audit log", "auditID", auditID, "error", err.Error())
		}
		return 0, opErr
	}

	if err := complete(ctx, auditID, models.AuditSucceeded, ""); err != nil {
		logging.Logger.Warn("Failed to record success for audit log", "auditID", auditID, "error", err.Error())
	}
	return status, nil
}

// verifyAdminRole resolves the acting user's subject and bearer token, or writes an error
// response and returns ok=false. Trusts a valid X-Internal-Service-Token
// outright (see hasValidInternalServiceToken for why admin-web uses this
// instead of an Auth0 bearer token) but still requires an
// X-Acting-User-Sub header identifying who initiated the action, since
// every mutating route needs that for its audit log. Falls through to
// verifying an Auth0 bearer token's admin role otherwise, using the
// verified token's own subject as the acting user.
func verifyAdminRole(c *gin.Context, cache *auth0.JWKSCache, config auth0.Config) (string, string, bool) {
	if hasValidInternalServiceToken(c) {
		actingUserSub := c.GetHeader(actingUserSubHeader)
		if actingUserSub == "" {
			c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: "X-Acting-User-Sub header is required"})
			return "", "", false
		}
		return actingUserSub, "", true
	}

	token := bearerToken(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, apiv.ErrorVO{Error: "unauthorized", Message: "missing or invalid credentials"})
		return "", "", false
	}

	claims, err := cache.Verify(c.Request.Context(), token, config)
	if err != nil {
		c.JSON(http.StatusUnauthorized, apiv.ErrorVO{Error: "unauthorized", Message: "missing or invalid credentials"})
		return "", "", false
	}

	roles, err := models.ListRolesForSubject(c.Request.Context(), claims.Subject)
	if err != nil {
		logging.Logger.Error("Failed to look up roles", "error", err.Error())
		c.JSON(http.StatusInternalServerError, apiv.ErrorVO{Error: "query_failed", Message: "failed to verify admin role"})
		return "", "", false
	}
	hasAdmin := false
	for _, r := range roles {
		if r.Role == models.RoleAdmin {
			hasAdmin = true
			break
		}
	}
	if !hasAdmin {
		c.JSON(http.StatusForbidden, apiv.ErrorVO{Error: "forbidden", Message: "admin role required"})
		return "", "", false
	}
	return claims.Subject, token, true
}

// hasValidInternalServiceToken reports whether the request presented the
// correct X-Internal-Service-Token header, compared constant-time against
// INTERNAL_SERVICE_TOKEN. Always false when INTERNAL_SERVICE_TOKEN is unset
// - the internal-auth path is then permanently disabled rather than
// trusting an empty token.
func hasValidInternalServiceToken(c *gin.Context) bool {
	expected := util.GetEnv(constants.INTERNAL_SERVICE_TOKEN, "")
	if expected == "" {
		return false
	}
	presented := c.GetHeader(internalServiceTokenHeader)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) == 1
}

// resolveActingUser resolves the acting user's Auth0 subject to their canonical
// users._id. For bearer-token callers, uses authzClient.ResolveUserID. For
// internal-service-token callers, calls users-api's /internal/resolve-subjects
// with the provided subject. Returns an error if resolution fails or returns
// empty, so the caller can fail closed.
func resolveActingUser(ctx context.Context, authzClient *authz.Client, usersBaseURL, actingUserSub, token string) (string, error) {
	if token != "" {
		userID := authzClient.ResolveUserID(ctx, token)
		if userID == "" {
			return "", fmt.Errorf("resolveActingUser: bearer token resolved to empty user ID")
		}
		return userID, nil
	}

	// Internal service token path: call users-api's /internal/resolve-subjects
	if usersBaseURL == "" {
		return "", fmt.Errorf("resolveActingUser: USERS_API_URL not configured")
	}

	// Use the same internal service token that auth-api uses for its own auth
	internalToken := util.GetEnv(constants.INTERNAL_SERVICE_TOKEN, "")
	if internalToken == "" {
		return "", fmt.Errorf("resolveActingUser: INTERNAL_SERVICE_TOKEN not configured")
	}

	type resolveRequest struct {
		Subjects []string `json:"subjects"`
	}
	type resolveResponse map[string]string

	body, err := json.Marshal(resolveRequest{Subjects: []string{actingUserSub}})
	if err != nil {
		return "", fmt.Errorf("resolveActingUser: marshal request: %w", err)
	}

	httpClient := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, usersBaseURL+"/internal/resolve-subjects", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("resolveActingUser: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+internalToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("resolveActingUser: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("resolveActingUser: unexpected status %d from users-api", resp.StatusCode)
	}

	var out resolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("resolveActingUser: decode response: %w", err)
	}

	userID := out[actingUserSub]
	if userID == "" {
		return "", fmt.Errorf("resolveActingUser: subject not resolved")
	}
	return userID, nil
}

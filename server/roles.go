package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	apiv "github.com/sweetrpg/api-core.go/vo"
	"github.com/sweetrpg/auth-api/auth0"
	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/auth-api/events"
	"github.com/sweetrpg/auth-api/models"
	"github.com/sweetrpg/auth-api/registry"
	"github.com/sweetrpg/authz-client.go/authz"
	"github.com/sweetrpg/common.go/logging"
	"github.com/sweetrpg/common.go/util"
)

// Store and audit operations the mutating handlers call. Variables so tests need no database.
var (
	hasRole         = models.HasRole
	insertRole      = models.AddRole
	deleteRole      = models.RemoveRole
	hasDenyEntry    = models.HasDenyEntry
	insertDenyEntry = models.AddDenyEntry
	deleteDenyEntry = models.RemoveDenyEntry
	audited         = performAudited
)

// eventEmitter publishes deny and role-removal changes after they commit (PADR-0039). Nil drops
// them with a warning.
var eventEmitter *events.Emitter

// SetEventEmitter wires the bus publisher; call it before serving.
func SetEventEmitter(e *events.Emitter) { eventEmitter = e }

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
	ensureUserResolver()
	authzClient := authz.NewClient("", usersBaseURL)

	group := g.Group("/api/admin")
	group.GET("/services", func(c *gin.Context) { listServices(c, cache, config) })
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

// List the services a user can be denied.
//
//	@Summary		List valid service names
//	@Description	The registered services, as {id, name}, for the deny-entry selector
//	@Tags			admin
//	@Produce		json
//	@Success		200	{array}		registry.Service
//	@Failure		401	{object}	apiv.ErrorVO
//	@Failure		403	{object}	apiv.ErrorVO
//	@Router			/api/admin/services [get]
func listServices(c *gin.Context, cache *auth0.JWKSCache, config auth0.Config) {
	if _, _, ok := verifyAdminRole(c, cache, config); !ok {
		return
	}
	c.JSON(http.StatusOK, registry.Services())
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
	_, token, ok := verifyAdminRole(c, cache, config)
	if !ok {
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
		summary, err := buildSummary(c.Request.Context(), subject, token)
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
	_, token, ok := verifyAdminRole(c, cache, config)
	if !ok {
		return
	}

	subject := c.Param("subject")
	if subject == "" {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: "invalid subject"})
		return
	}
	summary, err := buildSummary(c.Request.Context(), subject, token)
	if err != nil {
		logging.Logger.Error("Failed to build roles summary", "error", err.Error())
		c.JSON(http.StatusInternalServerError, apiv.ErrorVO{Error: "query_failed", Message: "failed to get subject"})
		return
	}
	c.JSON(http.StatusOK, summary)
}

func buildSummary(ctx context.Context, subject, adminToken string) (subjectRolesSummary, error) {
	roles, err := models.ListRolesFor(ctx, targetPrincipal(ctx, subject, adminToken))
	if err != nil {
		return subjectRolesSummary{}, err
	}
	denials, err := models.ListDenyEntriesFor(ctx, targetPrincipal(ctx, subject, adminToken))
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

	actingUserID, ok := actingUserForAudit(c.Request.Context(), authzClient, usersBaseURL, actingUserSub, token)
	if !ok {
		c.JSON(http.StatusServiceUnavailable, apiv.ErrorVO{Error: "user_resolution_unavailable", Message: "unable to resolve the calling user"})
		return
	}

	subject := c.Param("subject")
	p := targetPrincipal(c.Request.Context(), subject, token)
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

	status, err := audited(c.Request.Context(), actingUserID, "add_role", subject, string(role),
		func(ctx context.Context) (int, error) {
			exists, err := hasRole(ctx, p, role)
			if err != nil {
				return 0, err
			}
			if exists {
				return http.StatusNoContent, nil
			}
			if err := insertRole(ctx, p, role, actingUserID); err != nil {
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

	actingUserID, ok := actingUserForAudit(c.Request.Context(), authzClient, usersBaseURL, actingUserSub, token)
	if !ok {
		c.JSON(http.StatusServiceUnavailable, apiv.ErrorVO{Error: "user_resolution_unavailable", Message: "unable to resolve the calling user"})
		return
	}

	subject := c.Param("subject")
	p := targetPrincipal(c.Request.Context(), subject, token)
	if subject == "" {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: "invalid subject"})
		return
	}
	role, ok := models.ParseRole(c.Param("role"))
	if !ok {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: "invalid role"})
		return
	}

	held := false
	status, err := audited(c.Request.Context(), actingUserID, "remove_role", subject, string(role),
		func(ctx context.Context) (int, error) {
			var err error
			if held, err = hasRole(ctx, p, role); err != nil {
				return 0, err
			}
			if err := deleteRole(ctx, p, role); err != nil {
				return 0, err
			}
			return http.StatusNoContent, nil
		})
	if err != nil {
		logging.Logger.Error("Failed to remove role", "error", err.Error())
		c.JSON(http.StatusInternalServerError, apiv.ErrorVO{Error: "audit_failed", Message: "failed to remove role"})
		return
	}
	if held {
		eventEmitter.Emit(events.KindRoleRemoved, subject, events.EventData{Role: string(role)})
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

	actingUserID, ok := actingUserForAudit(c.Request.Context(), authzClient, usersBaseURL, actingUserSub, token)
	if !ok {
		c.JSON(http.StatusServiceUnavailable, apiv.ErrorVO{Error: "user_resolution_unavailable", Message: "unable to resolve the calling user"})
		return
	}

	subject := c.Param("subject")
	p := targetPrincipal(c.Request.Context(), subject, token)
	if subject == "" {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: "invalid subject"})
		return
	}
	var req denyEntryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: err.Error()})
		return
	}

	if !registry.Known(req.Service) {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "unknown_service", Message: "unknown service"})
		return
	}

	status, err := audited(c.Request.Context(), actingUserID, "add_deny_entry", subject, req.Service,
		func(ctx context.Context) (int, error) {
			exists, err := hasDenyEntry(ctx, p, req.Service)
			if err != nil {
				return 0, err
			}
			if exists {
				return http.StatusNoContent, nil
			}
			if err := insertDenyEntry(ctx, p, req.Service, actingUserID); err != nil {
				return 0, err
			}
			return http.StatusCreated, nil
		})
	if err != nil {
		logging.Logger.Error("Failed to add deny entry", "error", err.Error())
		c.JSON(http.StatusInternalServerError, apiv.ErrorVO{Error: "audit_failed", Message: "failed to add deny entry"})
		return
	}
	if status == http.StatusCreated {
		eventEmitter.Emit(events.KindDeny, subject, events.EventData{Service: req.Service})
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

	actingUserID, ok := actingUserForAudit(c.Request.Context(), authzClient, usersBaseURL, actingUserSub, token)
	if !ok {
		c.JSON(http.StatusServiceUnavailable, apiv.ErrorVO{Error: "user_resolution_unavailable", Message: "unable to resolve the calling user"})
		return
	}

	subject := c.Param("subject")
	p := targetPrincipal(c.Request.Context(), subject, token)
	if subject == "" {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: "invalid subject"})
		return
	}
	service := c.Param("service")
	if service == "" {
		c.JSON(http.StatusBadRequest, apiv.ErrorVO{Error: "invalid_request", Message: "invalid service"})
		return
	}

	status, err := audited(c.Request.Context(), actingUserID, "remove_deny_entry", subject, service,
		func(ctx context.Context) (int, error) {
			if err := deleteDenyEntry(ctx, p, service); err != nil {
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

// verifyToken verifies a bearer token and returns its Auth0 subject. A variable so tests can
// stand in for Auth0's JWKS.
var verifyToken = func(ctx context.Context, cache *auth0.JWKSCache, token string, config auth0.Config) (string, error) {
	claims, err := cache.Verify(ctx, token, config)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// holdsAdminRole reports whether the principal has the admin role. A variable so tests need no
// database.
var holdsAdminRole = func(ctx context.Context, p models.Principal) (bool, error) {
	roles, err := models.ListRolesFor(ctx, p)
	if err != nil {
		return false, err
	}
	for _, r := range roles {
		if r.Role == models.RoleAdmin {
			return true, nil
		}
	}
	return false, nil
}

// verifyAdminRole resolves the acting administrator's subject and bearer token, or writes an
// error response and returns ok=false. The only credential is an Auth0 bearer token whose subject
// holds the admin role (PADR-0037: no service tokens); the token's own subject is the acting user.
func verifyAdminRole(c *gin.Context, cache *auth0.JWKSCache, config auth0.Config) (string, string, bool) {
	token := bearerToken(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, apiv.ErrorVO{Error: "unauthorized", Message: "missing or invalid credentials"})
		return "", "", false
	}

	subject, err := verifyToken(c.Request.Context(), cache, token, config)
	if err != nil {
		c.JSON(http.StatusUnauthorized, apiv.ErrorVO{Error: "unauthorized", Message: "missing or invalid credentials"})
		return "", "", false
	}

	isAdmin, err := holdsAdminRole(c.Request.Context(), ownPrincipal(c.Request.Context(), subject, token))
	if err != nil {
		logging.Logger.Error("Failed to look up roles", "error", err.Error())
		c.JSON(http.StatusInternalServerError, apiv.ErrorVO{Error: "query_failed", Message: "failed to verify admin role"})
		return "", "", false
	}
	if !isAdmin {
		c.JSON(http.StatusForbidden, apiv.ErrorVO{Error: "forbidden", Message: "admin role required"})
		return "", "", false
	}
	return subject, token, true
}

// actingUserForAudit returns who to attribute an admin write to. Attribution must not block the
// action, so when the canonical ID cannot be resolved (users-api unreachable, not configured, or
// refusing the lookup) the cause is logged at ERROR and the acting Auth0 subject is recorded
// instead. ok is false only when there is nothing at all to attribute to.
func actingUserForAudit(ctx context.Context, authzClient *authz.Client, usersBaseURL, actingUserSub, token string) (string, bool) {
	id, err := resolveActingUser(ctx, authzClient, usersBaseURL, actingUserSub, token)
	if err == nil {
		return id, true
	}
	logging.Logger.Error("could not resolve the acting user's canonical id; recording the Auth0 subject in the audit trail", "subject", actingUserSub, "error", err.Error())
	if actingUserSub == "" {
		return "", false
	}
	return actingUserSub, true
}

// resolveActingUser resolves the acting user's Auth0 subject to their canonical
// users._id with the caller's own bearer token (authzClient.ResolveUserID). Returns an error when
// there is no token or it resolves to nothing; actingUserForAudit then records the subject.
func resolveActingUser(ctx context.Context, authzClient *authz.Client, usersBaseURL, actingUserSub, token string) (string, error) {
	if token != "" {
		userID := authzClient.ResolveUserID(ctx, token)
		if userID == "" {
			return "", fmt.Errorf("resolveActingUser: bearer token resolved to empty user ID")
		}
		return userID, nil
	}

	// An internal-service-token caller has no user bearer token to resolve with.
	return "", fmt.Errorf("resolveActingUser: no bearer token to resolve %q with", actingUserSub)
}

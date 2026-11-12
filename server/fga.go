package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sweetrpg/auth-api/auth0"
	"github.com/sweetrpg/auth-api/fga"
	"github.com/sweetrpg/auth-api/models"
	"github.com/sweetrpg/common.go/logging"
)

const (
	maxTupleBatch     = 100
	defaultTuplePage  = 50
	maxTuplePage      = 100
	authzUnavailable  = "authz_unavailable"
	fgaWriteAction    = "openfga_write_tuples"
	userPrincipalType = "user:"
)

type checkRelationRequest struct {
	Object   string `json:"object" binding:"required"`
	Relation string `json:"relation" binding:"required"`
}

type checkRelationResponse struct {
	Allowed bool `json:"allowed"`
}

type tupleWriteRequest struct {
	Writes  []fga.Tuple `json:"writes"`
	Deletes []fga.Tuple `json:"deletes"`
}

type tupleReadResponse struct {
	Tuples            []fga.Tuple `json:"tuples"`
	ContinuationToken string      `json:"continuation_token"`
}

// fgaHandlers serves relationship checks and the internal tuple endpoints. The store is an
// interface so tests run without OpenFGA.
type fgaHandlers struct {
	store  fga.Store
	cache  *auth0.JWKSCache
	config auth0.Config
}

// Seams for tests. principalFor resolves the caller's canonical user; holdsWriterRole checks the
// openfga-writer role; auditedWrite records and runs an admin write.
var (
	principalFor    = ownPrincipal
	holdsWriterRole = func(ctx context.Context, p models.Principal) (bool, error) {
		return models.HasRole(ctx, p, models.RoleOpenFGAWriter)
	}
	auditedWrite = performAudited
)

// SetupFGAHandlers registers POST /authz/check-relation and the internal tuple endpoints. Call
// it once at startup with the store Bootstrap resolved.
func SetupFGAHandlers(g *gin.Engine, cache *auth0.JWKSCache, config auth0.Config, store fga.Store) {
	ensureUserResolver()
	h := fgaHandlers{store: store, cache: cache, config: config}
	g.POST("/authz/check-relation", h.checkRelation)
	g.POST("/internal/openfga/tuples", h.writeTuples)
	g.GET("/internal/openfga/tuples", h.readTuples)
}

// checkRelation answers whether the caller's subject holds a relation on an object. An invalid
// token never reaches the store.
func (h fgaHandlers) checkRelation(c *gin.Context) {
	var req checkRelationRequest
	if err := c.ShouldBindJSON(&req); err != nil || !validObject(req.Object) {
		c.JSON(http.StatusBadRequest, authzErrorResponse{Error: "invalid_request"})
		return
	}
	token := bearerToken(c)
	if token == "" {
		invalidTokenResponse(c)
		return
	}
	subject, err := verifyToken(c.Request.Context(), h.cache, token, h.config)
	if err != nil {
		invalidTokenResponse(c)
		return
	}
	// Tuples belong to the person, so the check is keyed on the canonical user ID. Without one
	// (users-api unreachable, or the login has no user) the answer would depend on which login
	// was used, so fail closed.
	userID := principalFor(c.Request.Context(), subject, token).UserID
	if userID == "" {
		logging.Logger.Warn("OpenFGA check denied; canonical user unresolved", "subject", subject)
		c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
		return
	}

	allowed, err := h.store.Check(c.Request.Context(), fga.Tuple{
		User: userPrincipalType + userID, Relation: req.Relation, Object: req.Object,
	})
	if err != nil {
		logging.Logger.Error("OpenFGA check failed; denying", "object", req.Object, "relation", req.Relation, "error", err.Error())
		c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
		return
	}
	c.JSON(http.StatusOK, checkRelationResponse{Allowed: allowed})
}

// writeTuples applies a batch of tuple writes and deletes atomically, after recording the attempt
// in the audit log.
func (h fgaHandlers) writeTuples(c *gin.Context) {
	subject, ok := h.requireWriter(c)
	if !ok {
		return
	}
	var req tupleWriteRequest
	if err := c.ShouldBindJSON(&req); err != nil || !validTupleBatch(req) {
		c.JSON(http.StatusBadRequest, authzErrorResponse{Error: "invalid_request"})
		return
	}

	detail := auditDetail(req)
	_, err := auditedWrite(c.Request.Context(), subject, fgaWriteAction, "", detail, func(ctx context.Context) (int, error) {
		return http.StatusOK, h.store.Write(ctx, req.Writes, req.Deletes)
	})
	if err != nil {
		logging.Logger.Error("OpenFGA tuple write failed", "error", err.Error())
		switch {
		case errors.Is(err, fga.ErrInvalid):
			c.JSON(http.StatusBadRequest, authzErrorResponse{Error: "invalid_tuples"})
		case errors.Is(err, fga.ErrConflict):
			c.JSON(http.StatusConflict, authzErrorResponse{Error: "tuple_conflict"})
		default:
			c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"writes": len(req.Writes), "deletes": len(req.Deletes)})
}

// readTuples returns one page of tuples on an object for reconciliation.
func (h fgaHandlers) readTuples(c *gin.Context) {
	if _, ok := h.requireWriter(c); !ok {
		return
	}
	object := c.Query("object")
	if !validObject(object) {
		c.JSON(http.StatusBadRequest, authzErrorResponse{Error: "invalid_request"})
		return
	}
	pageSize, ok := parsePageSize(c.Query("page_size"))
	if !ok {
		c.JSON(http.StatusBadRequest, authzErrorResponse{Error: "invalid_request"})
		return
	}

	tuples, next, err := h.store.Read(c.Request.Context(), object, pageSize, c.Query("continuation_token"))
	if err != nil {
		logging.Logger.Error("OpenFGA tuple read failed", "object", object, "error", err.Error())
		c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
		return
	}
	c.JSON(http.StatusOK, tupleReadResponse{Tuples: tuples, ContinuationToken: next})
}

// requireWriter verifies the bearer token and that its subject holds openfga-writer. It writes
// the error response and returns ok=false on any failure.
func (h fgaHandlers) requireWriter(c *gin.Context) (string, bool) {
	token := bearerToken(c)
	if token == "" {
		invalidTokenResponse(c)
		return "", false
	}
	subject, err := verifyToken(c.Request.Context(), h.cache, token, h.config)
	if err != nil {
		invalidTokenResponse(c)
		return "", false
	}
	holds, err := holdsWriterRole(c.Request.Context(), principalFor(c.Request.Context(), subject, token))
	if err != nil {
		logging.Logger.Error("Failed to look up roles", "error", err.Error())
		c.JSON(http.StatusInternalServerError, authzErrorResponse{Error: "query_failed"})
		return "", false
	}
	if !holds {
		c.JSON(http.StatusForbidden, authzErrorResponse{Error: "forbidden"})
		return "", false
	}
	return subject, true
}

// validObject requires the "type:id" form OpenFGA uses.
func validObject(s string) bool {
	typ, id, ok := strings.Cut(s, ":")
	return ok && typ != "" && id != "" && !strings.ContainsAny(s, " \t\n#")
}

// auditDetail lists every tuple in the batch (at most maxTupleBatch), so the audit log shows which
// relationships changed.
func auditDetail(req tupleWriteRequest) string {
	var b strings.Builder
	b.WriteString("writes=" + strconv.Itoa(len(req.Writes)) + " deletes=" + strconv.Itoa(len(req.Deletes)))
	for _, t := range req.Writes {
		b.WriteString("; +" + t.User + " " + t.Relation + " " + t.Object)
	}
	for _, t := range req.Deletes {
		b.WriteString("; -" + t.User + " " + t.Relation + " " + t.Object)
	}
	return b.String()
}

// validUser requires "user:<canonical id>". An Auth0 subject ("provider|id") is rejected so
// tuples can't be keyed on a login.
func validUser(s string) bool {
	id, ok := strings.CutPrefix(s, userPrincipalType)
	return ok && id != "" && !strings.ContainsAny(id, " \t\n#|:*")
}

func validTupleBatch(req tupleWriteRequest) bool {
	n := len(req.Writes) + len(req.Deletes)
	if n == 0 || n > maxTupleBatch {
		return false
	}
	for _, t := range append(append([]fga.Tuple{}, req.Writes...), req.Deletes...) {
		if !validUser(t.User) || t.Relation == "" || !validObject(t.Object) {
			return false
		}
	}
	return true
}

func parsePageSize(raw string) (int32, bool) {
	if raw == "" {
		return defaultTuplePage, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > maxTuplePage {
		return 0, false
	}
	return int32(n), true
}

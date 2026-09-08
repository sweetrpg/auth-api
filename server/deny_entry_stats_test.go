package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sweetrpg/auth-api/auth0"
	"github.com/sweetrpg/common.go/logging"
)

func newDenyStatsRouter(t *testing.T) *gin.Engine {
	t.Helper()
	logging.Init()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	setupRolesHandlers(r, auth0.NewJWKSCache(), auth0.Config{Domain: "test.auth0.dev", Audience: "test-audience"})
	return r
}

// GET /api/admin/deny-entries/stats with no credentials is rejected before any DB access.
func TestDenyEntryStats_RejectsMissingCredentials(t *testing.T) {
	r := newDenyStatsRouter(t)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/admin/deny-entries/stats", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestDenyEntryStats_RejectsMismatchedInternalToken(t *testing.T) {
	t.Setenv("INTERNAL_SERVICE_TOKEN", "test-internal-token")
	r := newDenyStatsRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/deny-entries/stats", nil)
	req.Header.Set(internalServiceTokenHeader, "wrong-token")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// A valid internal token without X-Acting-User-Sub is a 400 from verifyAdminRole - which also
// proves the static /deny-entries/stats route matched rather than 404ing or being captured by
// the /deny-entries/:subject param route.
func TestDenyEntryStats_RouteMatchesAndRequiresActingUser(t *testing.T) {
	t.Setenv("INTERNAL_SERVICE_TOKEN", "test-internal-token")
	r := newDenyStatsRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/deny-entries/stats", nil)
	req.Header.Set(internalServiceTokenHeader, "test-internal-token")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (route should match and demand X-Acting-User-Sub)", rec.Code, http.StatusBadRequest)
	}
}

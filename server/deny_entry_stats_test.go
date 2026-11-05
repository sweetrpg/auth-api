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

func TestDenyEntryStats_RejectsANonAdmin(t *testing.T) {
	stubAdminAuth(t)
	r := newDenyStatsRouter(t)
	rec := serve(r, withBearer(httptest.NewRequest(http.MethodGet, "/api/admin/deny-entries/stats", nil), userBearer))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sweetrpg/auth-api/auth0"
	"github.com/sweetrpg/common.go/logging"
)

func verify(t *testing.T, method string, headers map[string]string) (sub, token string, ok bool, code int) {
	t.Helper()
	logging.Init()
	gin.SetMode(gin.TestMode)
	stubAdminAuth(t)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(method, "/api/admin/roles", nil)
	for k, v := range headers {
		c.Request.Header.Set(k, v)
	}
	sub, token, ok = verifyAdminRole(c, auth0.NewJWKSCache(), auth0.Config{})
	return sub, token, ok, rec.Code
}

func TestAdminBearerIsAccepted(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		sub, token, ok, _ := verify(t, m, map[string]string{"Authorization": "Bearer " + adminBearer})
		if !ok || sub != "auth0|admin" || token != adminBearer {
			t.Errorf("%s: sub = %q token = %q ok = %v", m, sub, token, ok)
		}
	}
}

func TestNonAdminBearerIsForbidden(t *testing.T) {
	_, _, ok, code := verify(t, http.MethodGet, map[string]string{"Authorization": "Bearer " + userBearer})
	if ok || code != http.StatusForbidden {
		t.Errorf("ok = %v, status = %d, want 403", ok, code)
	}
}

func TestMissingOrBadBearerIsUnauthorized(t *testing.T) {
	for name, h := range map[string]map[string]string{
		"none":       nil,
		"bad token":  {"Authorization": "Bearer nope"},
		"not bearer": {"Authorization": "Basic abc"},
	} {
		if _, _, ok, code := verify(t, http.MethodGet, h); ok || code != http.StatusUnauthorized {
			t.Errorf("%s: ok = %v, status = %d, want 401", name, ok, code)
		}
	}
}

// A service token is not a credential (PADR-0037), even with the old env var set.
func TestInternalServiceTokenHeaderIsNoLongerAccepted(t *testing.T) {
	t.Setenv("INTERNAL_SERVICE_TOKEN", "test-internal-token")
	_, _, ok, code := verify(t, http.MethodGet, map[string]string{"X-Internal-Service-Token": "test-internal-token", "X-Acting-User-Sub": "auth0|admin"})
	if ok || code != http.StatusUnauthorized {
		t.Errorf("ok = %v, status = %d, want 401", ok, code)
	}
}

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sweetrpg/auth-api/auth0"
	"github.com/sweetrpg/common.go/logging"
)

func verify(t *testing.T, method string, headers map[string]string) (sub string, ok bool, code int) {
	t.Helper()
	t.Setenv("INTERNAL_SERVICE_TOKEN", "test-internal-token")
	logging.Init()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(method, "/api/admin/roles", nil)
	for k, v := range headers {
		c.Request.Header.Set(k, v)
	}
	sub, _, ok = verifyAdminRole(c, auth0.NewJWKSCache(), auth0.Config{Domain: "test.auth0.dev", Audience: "test-audience"})
	return sub, ok, rec.Code
}

// admin-web sends no X-Acting-User-Sub on read-only calls (the role listing, the restricted-user
// count): nothing is audited, so the header is only needed for mutations.
func TestInternalTokenReadsNeedNoActingUser(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		_, ok, code := verify(t, m, map[string]string{internalServiceTokenHeader: "test-internal-token"})
		if !ok || code != http.StatusOK {
			t.Errorf("%s: ok = %v, status = %d, want accepted", m, ok, code)
		}
	}
}

func TestInternalTokenReadStillReturnsTheActingUserWhenGiven(t *testing.T) {
	sub, ok, _ := verify(t, http.MethodGet, map[string]string{internalServiceTokenHeader: "test-internal-token", actingUserSubHeader: "auth0|admin"})
	if !ok || sub != "auth0|admin" {
		t.Errorf("sub = %q ok = %v", sub, ok)
	}
}

func TestInternalTokenMutationsStillNeedTheActingUser(t *testing.T) {
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		_, ok, code := verify(t, m, map[string]string{internalServiceTokenHeader: "test-internal-token"})
		if ok || code != http.StatusBadRequest {
			t.Errorf("%s: ok = %v, status = %d, want 400", m, ok, code)
		}
	}
}

func TestReadWithAWrongInternalTokenIsStillRejected(t *testing.T) {
	_, ok, code := verify(t, http.MethodGet, map[string]string{internalServiceTokenHeader: "wrong"})
	if ok || code != http.StatusUnauthorized {
		t.Errorf("ok = %v, status = %d, want 401", ok, code)
	}
}

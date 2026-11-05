package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sweetrpg/auth-api/auth0"
	"github.com/sweetrpg/auth-api/models"
)

// Bearer tokens the stubbed verifier understands.
const (
	adminBearer = "admin-bearer"
	userBearer  = "user-bearer"
)

// stubAdminAuth replaces JWKS verification and the role lookup: adminBearer is the subject
// auth0|admin holding the admin role, userBearer is auth0|user without it, anything else fails.
func stubAdminAuth(t *testing.T) {
	t.Helper()
	origVerify, origAdmin := verifyToken, holdsAdminRole
	verifyToken = func(_ context.Context, _ *auth0.JWKSCache, token string, _ auth0.Config) (string, error) {
		switch token {
		case adminBearer:
			return "auth0|admin", nil
		case userBearer:
			return "auth0|user", nil
		}
		return "", errors.New("bad token")
	}
	holdsAdminRole = func(_ context.Context, p models.Principal) (bool, error) { return p.Subject == "auth0|admin", nil }
	t.Cleanup(func() { verifyToken, holdsAdminRole = origVerify, origAdmin })
}

func withBearer(req *http.Request, token string) *http.Request {
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func serve(r http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

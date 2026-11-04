package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sweetrpg/common.go/logging"
)

func usersStub(t *testing.T, status int, resolved map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(resolved)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestActingUserForAudit(t *testing.T) {
	t.Setenv("INTERNAL_SERVICE_TOKEN", "test-internal-token")
	logging.Init()
	const sub = "auth0|admin"
	ok200 := usersStub(t, http.StatusOK, map[string]string{sub: "canonical-1"})
	unauthorized := usersStub(t, http.StatusUnauthorized, nil)
	unknown := usersStub(t, http.StatusOK, map[string]string{})

	cases := []struct {
		name   string
		url    string
		sub    string
		want   string
		wantOK bool
	}{
		{"resolves to the canonical id", ok200.URL, sub, "canonical-1", true},
		{"users-api rejects the lookup: record the subject", unauthorized.URL, sub, sub, true},
		{"users-api does not know the subject: record the subject", unknown.URL, sub, sub, true},
		{"users-api url not configured: record the subject", "", sub, sub, true},
		{"nothing to attribute to", "", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := actingUserForAudit(context.Background(), nil, c.url, c.sub, "")
			if got != c.want || ok != c.wantOK {
				t.Errorf("got %q, %v; want %q, %v", got, ok, c.want, c.wantOK)
			}
		})
	}
}

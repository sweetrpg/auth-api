package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sweetrpg/authz-client.go/authz"
	"github.com/sweetrpg/common.go/logging"
)

// profileStub stands in for users-api's GET /profile, which answers for the bearer's own user.
func profileStub(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/profile" || r.Header.Get("Authorization") != "Bearer admin-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"user_id": "canonical-1"})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestActingUserForAudit(t *testing.T) {
	logging.Init()
	const sub = "auth0|admin"
	ok := profileStub(t, http.StatusOK)
	notFound := profileStub(t, http.StatusNotFound)

	cases := []struct {
		name   string
		url    string
		sub    string
		token  string
		want   string
		wantOK bool
	}{
		{"bearer resolves to the canonical id", ok.URL, sub, "admin-token", "canonical-1", true},
		{"profile not found: record the subject", notFound.URL, sub, "admin-token", sub, true},
		{"users-api unreachable: record the subject", "", sub, "admin-token", sub, true},
		{"no bearer (internal-token caller): record the subject", ok.URL, sub, "", sub, true},
		{"nothing to attribute to", "", "", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, gotOK := actingUserForAudit(context.Background(), authz.NewClient("", c.url), c.url, c.sub, c.token)
			if got != c.want || gotOK != c.wantOK {
				t.Errorf("got %q, %v; want %q, %v", got, gotOK, c.want, c.wantOK)
			}
		})
	}
}

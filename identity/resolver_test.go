package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sweetrpg/common.go/logging"
)

// usersAPI stands in for users-api's resolve-subjects; it accepts only the admin bearer.
func usersAPI(t *testing.T, status int, answer map[string]string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	logging.Init()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer admin-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		var req map[string][]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		out := map[string]string{}
		for _, s := range req["subjects"] {
			if id, ok := answer[s]; ok {
				out[s] = id
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func counting(id string) (OwnLookup, *atomic.Int32) {
	var calls atomic.Int32
	return func(_ context.Context, token string) string {
		calls.Add(1)
		if token == "" {
			return ""
		}
		return id
	}, &calls
}

func TestOwnUsesTheCallersTokenAndCaches(t *testing.T) {
	lookup, calls := counting("u1")
	r := New("", lookup)
	for i := 0; i < 3; i++ {
		if got := r.Own(context.Background(), "auth0|a", "user-token"); got != "u1" {
			t.Fatalf("Own = %q", got)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("lookups = %d, want 1 (cached)", calls.Load())
	}
	if r.Cached("auth0|a") != "u1" {
		t.Error("Cached should return the stored answer")
	}
}

func TestOwnWithoutATokenResolvesNothing(t *testing.T) {
	lookup, calls := counting("u1")
	if got := New("", lookup).Own(context.Background(), "auth0|a", ""); got != "" || calls.Load() != 0 {
		t.Errorf("Own = %q after %d lookups, want empty and none", got, calls.Load())
	}
}

func TestCacheExpires(t *testing.T) {
	lookup, calls := counting("u1")
	r := New("", lookup)
	now := time.Now()
	r.now = func() time.Time { return now }
	r.Own(context.Background(), "auth0|a", "t")
	now = now.Add(2 * time.Minute)
	r.Own(context.Background(), "auth0|a", "t")
	if calls.Load() != 2 {
		t.Errorf("lookups = %d, want 2 after expiry", calls.Load())
	}
	if r.Cached("auth0|a") == "" {
		t.Error("the refreshed entry should be cached")
	}
}

func TestOtherUsesTheAdminBearer(t *testing.T) {
	srv, calls := usersAPI(t, http.StatusOK, map[string]string{"auth0|b": "u2"})
	r := New(srv.URL, nil)
	if got := r.Other(context.Background(), "auth0|b", "admin-token"); got != "u2" {
		t.Fatalf("Other = %q", got)
	}
	r.Other(context.Background(), "auth0|b", "admin-token")
	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1 (cached)", calls.Load())
	}
}

func TestOtherFallsBackToTheSubjectWhenItCannotResolve(t *testing.T) {
	srv, calls := usersAPI(t, http.StatusOK, nil)
	logging.Init()
	if got := New(srv.URL, nil).Other(context.Background(), "auth0|x", ""); got != "" || calls.Load() != 0 {
		t.Errorf("no admin token: %q after %d calls, want empty and no call", got, calls.Load())
	}
	if got := New(srv.URL, nil).Other(context.Background(), "auth0|x", "wrong"); got != "" {
		t.Errorf("rejected token = %q", got)
	}
	down, _ := usersAPI(t, http.StatusInternalServerError, nil)
	if got := New(down.URL, nil).Other(context.Background(), "auth0|x", "admin-token"); got != "" {
		t.Errorf("users-api error = %q", got)
	}
	if got := New("", nil).Other(context.Background(), "auth0|x", "admin-token"); got != "" {
		t.Errorf("unconfigured = %q", got)
	}
	var nilResolver *Resolver
	if nilResolver.Own(context.Background(), "s", "t") != "" || nilResolver.Other(context.Background(), "s", "t") != "" || nilResolver.Cached("s") != "" {
		t.Error("a nil resolver resolves nothing")
	}
}

func TestResolveBatchesLargeSubjectLists(t *testing.T) {
	answer := map[string]string{}
	var subjects []string
	for i := 0; i < 450; i++ {
		s := "auth0|" + string(rune('a'+i%26)) + string(rune('A'+i/26))
		subjects = append(subjects, s)
		answer[s] = "u" + s
	}
	srv, calls := usersAPI(t, http.StatusOK, answer)
	got, err := New(srv.URL, nil).Resolve(context.Background(), subjects, "admin-token")
	if err != nil || len(got) != len(subjects) || calls.Load() != 3 {
		t.Errorf("resolved %d of %d in %d calls, err %v", len(got), len(subjects), calls.Load(), err)
	}
}

func TestResolveNeedsAnAdminToken(t *testing.T) {
	srv, calls := usersAPI(t, http.StatusOK, nil)
	if _, err := New(srv.URL, nil).Resolve(context.Background(), []string{"a"}, ""); err == nil || calls.Load() != 0 {
		t.Errorf("err = %v after %d calls, want an error and no call", err, calls.Load())
	}
}

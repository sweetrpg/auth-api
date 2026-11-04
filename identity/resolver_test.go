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

func stub(t *testing.T, status int, answer map[string]string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	logging.Init()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Internal-Service-Token") != "tok" {
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

func TestUserIDResolvesAndCaches(t *testing.T) {
	srv, calls := stub(t, http.StatusOK, map[string]string{"auth0|a": "u1"})
	r := New(srv.URL, "tok")
	for i := 0; i < 3; i++ {
		if got := r.UserID(context.Background(), "auth0|a"); got != "u1" {
			t.Fatalf("UserID = %q", got)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1 (cached)", calls.Load())
	}
}

func TestCacheExpires(t *testing.T) {
	srv, calls := stub(t, http.StatusOK, map[string]string{"auth0|a": "u1"})
	r := New(srv.URL, "tok")
	now := time.Now()
	r.now = func() time.Time { return now }
	r.UserID(context.Background(), "auth0|a")
	now = now.Add(2 * time.Minute)
	r.UserID(context.Background(), "auth0|a")
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want 2 after expiry", calls.Load())
	}
}

func TestUnknownOrUnavailableReportsEmpty(t *testing.T) {
	srv, _ := stub(t, http.StatusOK, nil)
	if got := New(srv.URL, "tok").UserID(context.Background(), "auth0|x"); got != "" {
		t.Errorf("unknown subject = %q", got)
	}
	down, _ := stub(t, http.StatusInternalServerError, nil)
	if got := New(down.URL, "tok").UserID(context.Background(), "auth0|x"); got != "" {
		t.Errorf("users-api error = %q", got)
	}
	if got := New(srv.URL, "wrong").UserID(context.Background(), "auth0|x"); got != "" {
		t.Errorf("rejected token = %q", got)
	}
	if got := New("", "").UserID(context.Background(), "auth0|x"); got != "" {
		t.Errorf("unconfigured = %q", got)
	}
	var nilResolver *Resolver
	if got := nilResolver.UserID(context.Background(), "auth0|x"); got != "" {
		t.Errorf("nil resolver = %q", got)
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
	srv, calls := stub(t, http.StatusOK, answer)
	got, err := New(srv.URL, "tok").Resolve(context.Background(), subjects)
	if err != nil || len(got) != len(subjects) || calls.Load() != 3 {
		t.Errorf("resolved %d of %d in %d calls, err %v", len(got), len(subjects), calls.Load(), err)
	}
}

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sweetrpg/auth-api/auth0"
	"github.com/sweetrpg/auth-api/fga"
	"github.com/sweetrpg/auth-api/models"
	"github.com/sweetrpg/common.go/logging"
)

// fakeStore records calls and returns canned results.
type fakeStore struct {
	allowed  bool
	err      error
	checks   []fga.Tuple
	written  []fga.Tuple
	deleted  []fga.Tuple
	readPage []fga.Tuple
}

func (f *fakeStore) Check(_ context.Context, t fga.Tuple) (bool, error) {
	f.checks = append(f.checks, t)
	return f.allowed, f.err
}

func (f *fakeStore) Write(_ context.Context, writes, deletes []fga.Tuple) error {
	if f.err != nil {
		return f.err
	}
	f.written, f.deleted = writes, deletes
	return nil
}

func (f *fakeStore) Read(_ context.Context, _ string, _ int32, _ string) ([]fga.Tuple, string, error) {
	return f.readPage, "", f.err
}

// stubFGAAuth maps bearer tokens to subjects. writer-bearer holds openfga-writer; user-bearer does not.
func stubFGAAuth(t *testing.T) {
	t.Helper()
	origVerify, origWriter, origPrincipal, origAudit := verifyToken, holdsWriterRole, principalFor, auditedWrite
	verifyToken = func(_ context.Context, _ *auth0.JWKSCache, token string, _ auth0.Config) (string, error) {
		switch token {
		case "writer-bearer":
			return "auth0|job", nil
		case "user-bearer":
			return "auth0|user", nil
		case "user-second-login-bearer":
			return "google-oauth2|user", nil
		case "orphan-bearer":
			return "auth0|orphan", nil
		}
		return "", errors.New("bad token")
	}
	holdsWriterRole = func(_ context.Context, p models.Principal) (bool, error) { return p.Subject == "auth0|job", nil }
	// Both of one person's logins resolve to the same canonical user; orphan has none.
	userIDs := map[string]string{"auth0|user": "u-1", "google-oauth2|user": "u-1", "auth0|job": "u-job"}
	principalFor = func(_ context.Context, subject, _ string) models.Principal {
		return models.Principal{Subject: subject, UserID: userIDs[subject]}
	}
	auditedWrite = func(ctx context.Context, _ string, _ string, _ string, _ string, op func(context.Context) (int, error)) (int, error) {
		return op(ctx)
	}
	t.Cleanup(func() {
		verifyToken, holdsWriterRole, principalFor, auditedWrite = origVerify, origWriter, origPrincipal, origAudit
	})
}

func fgaEngine(store fga.Store) *gin.Engine {
	logging.Init()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	SetupFGAHandlers(r, nil, auth0.Config{}, store)
	return r
}

func TestCheckRelation(t *testing.T) {
	stubFGAAuth(t)
	cases := []struct {
		name        string
		body        string
		bearer      string
		store       *fakeStore
		wantStatus  int
		wantAllowed bool
		wantChecks  int
	}{
		{name: "allowed relation", body: `{"object":"volume-edit:1234","relation":"approver"}`, bearer: "user-bearer", store: &fakeStore{allowed: true}, wantStatus: http.StatusOK, wantAllowed: true, wantChecks: 1},
		{name: "denied relation", body: `{"object":"volume-edit:1234","relation":"approver"}`, bearer: "user-bearer", store: &fakeStore{allowed: false}, wantStatus: http.StatusOK, wantChecks: 1},
		{name: "invalid token never queries store", body: `{"object":"volume-edit:1234","relation":"approver"}`, bearer: "forged", store: &fakeStore{allowed: true}, wantStatus: http.StatusUnauthorized, wantChecks: 0},
		{name: "malformed object rejected", body: `{"object":"volume-edit","relation":"approver"}`, bearer: "user-bearer", store: &fakeStore{allowed: true}, wantStatus: http.StatusBadRequest, wantChecks: 0},
		{name: "store outage fails closed", body: `{"object":"volume-edit:1234","relation":"approver"}`, bearer: "user-bearer", store: &fakeStore{err: errors.New("down")}, wantStatus: http.StatusServiceUnavailable, wantChecks: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := withBearer(httptest.NewRequest(http.MethodPost, "/authz/check-relation", strings.NewReader(tc.body)), tc.bearer)
			rec := serve(fgaEngine(tc.store), req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if len(tc.store.checks) != tc.wantChecks {
				t.Errorf("store checks = %d, want %d", len(tc.store.checks), tc.wantChecks)
			}
			if tc.wantStatus == http.StatusOK {
				var got checkRelationResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
					t.Fatalf("decode body: %v", err)
				}
				if got.Allowed != tc.wantAllowed {
					t.Errorf("allowed = %v, want %v", got.Allowed, tc.wantAllowed)
				}
			}
		})
	}
}

func checkAs(t *testing.T, bearer string, store *fakeStore) int {
	t.Helper()
	req := withBearer(httptest.NewRequest(http.MethodPost, "/authz/check-relation", strings.NewReader(`{"object":"volume-edit:1","relation":"submitter"}`)), bearer)
	return serve(fgaEngine(store), req).Code
}

func TestCheckRelationKeysOnCanonicalUser(t *testing.T) {
	stubFGAAuth(t)
	store := &fakeStore{allowed: true}
	checkAs(t, "user-bearer", store)
	checkAs(t, "user-second-login-bearer", store)
	if len(store.checks) != 2 || store.checks[0] != store.checks[1] || store.checks[0].User != "user:u-1" {
		t.Fatalf("checks = %+v, want both logins to check user:u-1", store.checks)
	}
}

func TestCheckRelationFailsClosedWithoutCanonicalUser(t *testing.T) {
	stubFGAAuth(t)
	store := &fakeStore{allowed: true}
	if code := checkAs(t, "orphan-bearer", store); code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", code)
	}
	if len(store.checks) != 0 {
		t.Errorf("store was queried %d times for an unresolved user", len(store.checks))
	}
}

func TestTupleWriteRequiresWriterRole(t *testing.T) {
	stubFGAAuth(t)
	body := `{"writes":[{"user":"user:u-1","relation":"approver","object":"volume-edit:1"}]}`
	cases := []struct {
		name       string
		bearer     string
		wantStatus int
		wantWrites int
	}{
		{name: "no token", bearer: "", wantStatus: http.StatusUnauthorized},
		{name: "non-writer forbidden", bearer: "user-bearer", wantStatus: http.StatusForbidden},
		{name: "writer applies batch", bearer: "writer-bearer", wantStatus: http.StatusOK, wantWrites: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeStore{}
			req := withBearer(httptest.NewRequest(http.MethodPost, "/internal/openfga/tuples", strings.NewReader(body)), tc.bearer)
			rec := serve(fgaEngine(store), req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if len(store.written) != tc.wantWrites {
				t.Errorf("written = %d, want %d", len(store.written), tc.wantWrites)
			}
		})
	}
}

func TestTupleWriteFailureReturnsUnavailable(t *testing.T) {
	stubFGAAuth(t)
	store := &fakeStore{err: errors.New("transaction rolled back")}
	body := `{"writes":[{"user":"user:u-1","relation":"approver","object":"volume-edit:1"}]}`
	req := withBearer(httptest.NewRequest(http.MethodPost, "/internal/openfga/tuples", strings.NewReader(body)), "writer-bearer")
	if rec := serve(fgaEngine(store), req); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestTupleWriteRejectsEmptyBatch(t *testing.T) {
	stubFGAAuth(t)
	req := withBearer(httptest.NewRequest(http.MethodPost, "/internal/openfga/tuples", strings.NewReader(`{}`)), "writer-bearer")
	if rec := serve(fgaEngine(&fakeStore{}), req); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestTupleReadRequiresWriterRole(t *testing.T) {
	stubFGAAuth(t)
	store := &fakeStore{readPage: []fga.Tuple{{User: "user:u-1", Relation: "approver", Object: "volume-edit:1"}}}

	denied := withBearer(httptest.NewRequest(http.MethodGet, "/internal/openfga/tuples?object=volume-edit:1", nil), "user-bearer")
	if rec := serve(fgaEngine(store), denied); rec.Code != http.StatusForbidden {
		t.Fatalf("non-writer status = %d, want 403", rec.Code)
	}

	ok := withBearer(httptest.NewRequest(http.MethodGet, "/internal/openfga/tuples?object=volume-edit:1&page_size=10", nil), "writer-bearer")
	rec := serve(fgaEngine(store), ok)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "volume-edit:1") {
		t.Fatalf("writer read status = %d body %s", rec.Code, rec.Body.String())
	}
}

func TestParsePageSize(t *testing.T) {
	cases := map[string]struct {
		in   string
		want int32
		ok   bool
	}{
		"default": {in: "", want: defaultTuplePage, ok: true},
		"valid":   {in: "25", want: 25, ok: true},
		"zero":    {in: "0", ok: false},
		"too big": {in: "101", ok: false},
		"text":    {in: "many", ok: false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := parsePageSize(tc.in)
			if ok != tc.ok || (ok && got != tc.want) {
				t.Errorf("parsePageSize(%q) = %d, %v; want %d, %v", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func postTuples(t *testing.T, store *fakeStore, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := withBearer(httptest.NewRequest(http.MethodPost, "/internal/openfga/tuples", strings.NewReader(body)), "writer-bearer")
	return serve(fgaEngine(store), req)
}

func TestTupleWriteMapsStoreErrors(t *testing.T) {
	stubFGAAuth(t)
	body := `{"writes":[{"user":"user:u-1","relation":"approver","object":"volume-edit:1"}]}`
	cases := map[string]struct {
		err  error
		want int
	}{
		"invalid batch":     {err: fmt.Errorf("%w: unknown relation", fga.ErrInvalid), want: http.StatusBadRequest},
		"conflict":          {err: fga.ErrConflict, want: http.StatusConflict},
		"transport failure": {err: errors.New("openfga write failed"), want: http.StatusServiceUnavailable},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if rec := postTuples(t, &fakeStore{err: tc.err}, body); rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestTupleWriteRejectsLoginKeyedUsers(t *testing.T) {
	stubFGAAuth(t)
	for _, user := range []string{"user:auth0|abc", "approver:u-1", "user:", "user:*", "user:u-1#member"} {
		body := `{"writes":[{"user":"` + user + `","relation":"approver","object":"volume-edit:1"}]}`
		store := &fakeStore{}
		if rec := postTuples(t, store, body); rec.Code != http.StatusBadRequest || len(store.written) != 0 {
			t.Errorf("user %q: status = %d, written = %d; want 400 and no write", user, rec.Code, len(store.written))
		}
	}
}

func TestAuditDetailListsTuples(t *testing.T) {
	got := auditDetail(tupleWriteRequest{
		Writes:  []fga.Tuple{{User: "user:u-1", Relation: "approver", Object: "volume-edit:1"}},
		Deletes: []fga.Tuple{{User: "user:u-2", Relation: "submitter", Object: "volume-edit:2"}},
	})
	want := "writes=1 deletes=1; +user:u-1 approver volume-edit:1; -user:u-2 submitter volume-edit:2"
	if got != want {
		t.Errorf("auditDetail = %q, want %q", got, want)
	}
}

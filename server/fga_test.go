package server

import (
	"context"
	"encoding/json"
	"errors"
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
		}
		return "", errors.New("bad token")
	}
	holdsWriterRole = func(_ context.Context, p models.Principal) (bool, error) { return p.Subject == "auth0|job", nil }
	principalFor = func(_ context.Context, subject, _ string) models.Principal { return models.Principal{Subject: subject} }
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

func TestCheckRelationUsesSubjectAsUser(t *testing.T) {
	stubFGAAuth(t)
	store := &fakeStore{allowed: true}
	req := withBearer(httptest.NewRequest(http.MethodPost, "/authz/check-relation", strings.NewReader(`{"object":"volume-edit:1","relation":"submitter"}`)), "user-bearer")
	serve(fgaEngine(store), req)
	if len(store.checks) != 1 || store.checks[0].User != "user:auth0|user" {
		t.Fatalf("checks = %+v, want user:auth0|user", store.checks)
	}
}

func TestTupleWriteRequiresWriterRole(t *testing.T) {
	stubFGAAuth(t)
	body := `{"writes":[{"user":"user:a","relation":"approver","object":"volume-edit:1"}]}`
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
	body := `{"writes":[{"user":"user:a","relation":"approver","object":"volume-edit:1"}]}`
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
	store := &fakeStore{readPage: []fga.Tuple{{User: "user:a", Relation: "approver", Object: "volume-edit:1"}}}

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

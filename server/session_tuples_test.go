package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sweetrpg/api-core.go/ratelimit"
	"github.com/sweetrpg/auth-api/auth0"
	"github.com/sweetrpg/auth-api/fga"
	"github.com/sweetrpg/auth-api/models"
	"github.com/sweetrpg/common.go/logging"
)

// memStore is an in-memory OpenFGA with the session model's derived relations.
type memStore struct {
	mu       sync.Mutex
	tuples   []fga.Tuple
	checkErr error
	writeErr error
	writes   int
}

func (m *memStore) has(user, rel, obj string) bool {
	for _, t := range m.tuples {
		if t.User == user && t.Relation == rel && t.Object == obj {
			return true
		}
	}
	return false
}

func (m *memStore) Check(_ context.Context, t fga.Tuple) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.checkErr != nil {
		return false, m.checkErr
	}
	derived := map[string][]string{
		"can_view":    {"gm", "co_gm", "player", "observer"},
		"can_edit":    {"gm", "co_gm"},
		"can_approve": {"gm", "co_gm"},
		"gm":          {"gm"},
	}
	for _, r := range derived[t.Relation] {
		if m.has(t.User, r, t.Object) {
			return true, nil
		}
	}
	return false, nil
}

func (m *memStore) Write(_ context.Context, writes, deletes []fga.Tuple) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.writeErr != nil {
		return m.writeErr
	}
	m.writes++
	for _, d := range deletes {
		for i, t := range m.tuples {
			if t == d {
				m.tuples = append(m.tuples[:i], m.tuples[i+1:]...)
				break
			}
		}
	}
	for _, w := range writes {
		if !m.has(w.User, w.Relation, w.Object) {
			m.tuples = append(m.tuples, w)
		}
	}
	return nil
}

func (m *memStore) Read(_ context.Context, object string, pageSize int32, token string) ([]fga.Tuple, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var on []fga.Tuple
	for _, t := range m.tuples {
		if t.Object == object {
			on = append(on, t)
		}
	}
	start, _ := strconv.Atoi(token)
	end := min(start+int(pageSize), len(on))
	next := ""
	if end < len(on) {
		next = strconv.Itoa(end)
	}
	return on[min(start, len(on)):end], next, nil
}

func (m *memStore) on(object string) []fga.Tuple {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []fga.Tuple
	for _, t := range m.tuples {
		if t.Object == object {
			out = append(out, t)
		}
	}
	return out
}

// memMints is an in-memory session_mints collection with the conditional close.
type memMints struct {
	mu     sync.Mutex
	mints  map[string]*models.SessionMint
	closes int
}

func newMemMints() *memMints { return &memMints{mints: map[string]*models.SessionMint{}} }

func (m *memMints) Insert(_ context.Context, mint models.SessionMint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := mint
	m.mints[mint.ID] = &cp
	return nil
}

func (m *memMints) CountOpen(_ context.Context, user string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for _, x := range m.mints {
		if x.UserID == user && x.ClosedAt == nil {
			n++
		}
	}
	return n, nil
}

func (m *memMints) Close(_ context.Context, id, _ string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x, ok := m.mints[id]
	if !ok || x.ClosedAt != nil {
		return false, nil
	}
	x.ClosedAt = &now
	m.closes++
	return true, nil
}

func (m *memMints) ListOpenBefore(_ context.Context, cutoff time.Time, limit int64) ([]models.SessionMint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []models.SessionMint{}
	for _, x := range m.mints {
		if x.ClosedAt == nil && !x.CreatedAt.After(cutoff) && int64(len(out)) < limit {
			out = append(out, *x)
		}
	}
	return out, nil
}

func (m *memMints) open(user string) int {
	n, _ := m.CountOpen(context.Background(), user)
	return int(n)
}

// fakeLimiter allows every request unless told otherwise.
type fakeLimiter struct {
	deny map[string]bool // tier -> deny
	err  error
}

func (f *fakeLimiter) Check(_ context.Context, _, tier string) (ratelimit.Result, error) {
	if f.err != nil {
		return ratelimit.Result{}, f.err
	}
	if f.deny[tier] {
		return ratelimit.Result{RetryAfter: 7 * time.Second}, nil
	}
	return ratelimit.Result{Allowed: true}, nil
}

type sessEnv struct {
	r      *gin.Engine
	store  *memStore
	mints  *memMints
	limits SessionLimits
	denied map[string]bool
	audits []string
	auditE error
}

var testLimits = SessionLimits{MaxOpenMints: 100, MaxSessionTuples: 200, MintsPerUserHour: 20, MintsGlobalHour: 600, TupleReqsPerMinute: 120}

// newSessEnv wires the handlers over in-memory fakes. Tokens: gm-bearer (u-gm), co-bearer (u-co),
// player-bearer (u-pl), out-bearer (u-out), denied-bearer (u-den), orphan-bearer (no user),
// writer-bearer (the reconciler, holds openfga-writer).
func newSessEnv(t *testing.T, lim rateChecker, limits SessionLimits) *sessEnv {
	t.Helper()
	logging.Init()
	gin.SetMode(gin.TestMode)
	env := &sessEnv{store: &memStore{}, mints: newMemMints(), limits: limits, denied: map[string]bool{}}
	origVerify, origWriter, origPrincipal, origAudit, origDeny, origNew, origNow := verifyToken, holdsWriterRole, principalFor, auditedWrite, hasDenyEntry, newSessionID, nowFunc
	subjects := map[string]string{"gm-bearer": "auth0|gm", "co-bearer": "auth0|co", "player-bearer": "auth0|pl", "out-bearer": "auth0|out", "denied-bearer": "auth0|den", "orphan-bearer": "auth0|orphan", "writer-bearer": "auth0|job"}
	users := map[string]string{"auth0|gm": "u-gm", "auth0|co": "u-co", "auth0|pl": "u-pl", "auth0|out": "u-out", "auth0|den": "u-den", "auth0|job": "u-job"}
	verifyToken = func(_ context.Context, _ *auth0.JWKSCache, token string, _ auth0.Config) (string, error) {
		if s, ok := subjects[token]; ok {
			return s, nil
		}
		return "", errors.New("bad token")
	}
	holdsWriterRole = func(_ context.Context, p models.Principal) (bool, error) { return p.Subject == "auth0|job", nil }
	principalFor = func(_ context.Context, subject, _ string) models.Principal {
		return models.Principal{Subject: subject, UserID: users[subject]}
	}
	hasDenyEntry = func(_ context.Context, p models.Principal, service string) (bool, error) {
		if service != "initiative-api" {
			t.Errorf("deny check used service %q, want initiative-api", service)
		}
		return p.UserID == "u-den", nil
	}
	auditedWrite = func(ctx context.Context, _ string, action, target, _ string, op func(context.Context) (int, error)) (int, error) {
		env.audits = append(env.audits, action+" "+target)
		if env.auditE != nil {
			return 0, env.auditE
		}
		return op(ctx)
	}
	t.Cleanup(func() {
		verifyToken, holdsWriterRole, principalFor, auditedWrite, hasDenyEntry, newSessionID, nowFunc = origVerify, origWriter, origPrincipal, origAudit, origDeny, origNew, origNow
	})
	r := gin.New()
	registerSessionHandlers(r, fgaHandlers{store: env.store, config: auth0.Config{}}, env.mints, lim, limits)
	env.r = r
	return env
}

func (e *sessEnv) do(method, path, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return serve(e.r, withBearer(req, bearer))
}

func (e *sessEnv) mint(t *testing.T, bearer string) string {
	t.Helper()
	rec := e.do(http.MethodPost, "/authz/sessions", bearer, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint = %d %s", rec.Code, rec.Body)
	}
	m := regexp.MustCompile(`"session_id":"([0-9a-f]{24})"`).FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("mint body %s has no 24-hex session_id", rec.Body)
	}
	return m[1]
}

func (e *sessEnv) seed(id string, rels map[string]string) {
	for user, rel := range rels {
		e.store.tuples = append(e.store.tuples, fga.Tuple{User: "user:" + user, Relation: rel, Object: "session:" + id})
	}
}

func tuplesBody(id, writes, deletes string) string {
	return fmt.Sprintf(`{"session_id":%q,"writes":[%s],"deletes":[%s]}`, id, writes, deletes)
}

func tup(user, rel string) string { return fmt.Sprintf(`{"user":"user:%s","relation":%q}`, user, rel) }

func TestMintWritesTheCallersGMTupleAndRecordsTheMint(t *testing.T) {
	e := newSessEnv(t, &fakeLimiter{}, testLimits)

	id := e.mint(t, "gm-bearer")

	got := e.store.on("session:" + id)
	if len(got) != 1 || got[0].User != "user:u-gm" || got[0].Relation != "gm" {
		t.Fatalf("tuples = %+v, want one gm tuple for u-gm", got)
	}
	if e.mints.open("u-gm") != 1 {
		t.Errorf("open mints = %d, want 1", e.mints.open("u-gm"))
	}
	if other := e.mint(t, "gm-bearer"); other == id {
		t.Errorf("two mints returned the same id %s", id)
	}
	if len(e.audits) == 0 || !strings.HasPrefix(e.audits[0], "session_mint session:") {
		t.Errorf("audits = %v, want a session_mint row", e.audits)
	}
}

func TestMintRefusesDeniedUnresolvedAndBadTokens(t *testing.T) {
	e := newSessEnv(t, &fakeLimiter{}, testLimits)
	for bearer, want := range map[string]int{"denied-bearer": http.StatusForbidden, "orphan-bearer": http.StatusServiceUnavailable, "forged": http.StatusUnauthorized} {
		if rec := e.do(http.MethodPost, "/authz/sessions", bearer, ""); rec.Code != want {
			t.Errorf("%s mint = %d, want %d", bearer, rec.Code, want)
		}
	}
	if len(e.store.tuples) != 0 || e.store.writes != 0 {
		t.Errorf("a refused mint wrote tuples: %+v", e.store.tuples)
	}
}

func TestMintStopsAtTheOpenMintCap(t *testing.T) {
	limits := testLimits
	limits.MaxOpenMints = 3
	e := newSessEnv(t, &fakeLimiter{}, limits)
	for range 3 {
		e.mint(t, "gm-bearer")
	}

	rec := e.do(http.MethodPost, "/authz/sessions", "gm-bearer", "")

	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "mint_cap") {
		t.Fatalf("fourth mint = %d %s, want 429 mint_cap", rec.Code, rec.Body)
	}
	if rec := e.do(http.MethodPost, "/authz/sessions", "co-bearer", ""); rec.Code != http.StatusCreated {
		t.Errorf("another user's mint = %d, want 201 (the cap is per user)", rec.Code)
	}
}

func TestConcurrentMintsAt99OpenOvershootByAtMostTheConcurrency(t *testing.T) {
	e := newSessEnv(t, &fakeLimiter{}, testLimits)
	for i := range 99 {
		_ = e.mints.Insert(context.Background(), models.SessionMint{ID: fmt.Sprintf("%024x", i), UserID: "u-gm"})
	}
	const concurrent = 10
	var wg sync.WaitGroup
	for range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.do(http.MethodPost, "/authz/sessions", "gm-bearer", "")
		}()
	}
	wg.Wait()

	open := e.mints.open("u-gm")

	if open < 100 || open > 99+concurrent {
		t.Fatalf("open mints = %d, want between 100 and %d", open, 99+concurrent)
	}
}

func TestMintFailsClosedWithoutACounterStore(t *testing.T) {
	cases := map[string]rateChecker{
		"nil limiter":   nil,
		"redis down":    &fakeLimiter{err: errors.New("redis down")},
		"user budget":   &fakeLimiter{deny: map[string]bool{tierMintUser: true}},
		"global budget": &fakeLimiter{deny: map[string]bool{tierMintGlobal: true}},
	}
	want := map[string]int{"nil limiter": 503, "redis down": 503, "user budget": 429, "global budget": 429}
	for name, lim := range cases {
		t.Run(name, func(t *testing.T) {
			e := newSessEnv(t, lim, testLimits)

			rec := e.do(http.MethodPost, "/authz/sessions", "gm-bearer", "")

			if rec.Code != want[name] {
				t.Fatalf("status = %d, want %d", rec.Code, want[name])
			}
			if len(e.store.tuples) != 0 {
				t.Errorf("tuples written despite %s: %+v", name, e.store.tuples)
			}
			if want[name] == 429 && rec.Header().Get("Retry-After") != "7" {
				t.Errorf("Retry-After = %q, want 7", rec.Header().Get("Retry-After"))
			}
		})
	}
}

func TestMintClosesItsRecordWhenTheTupleWriteFails(t *testing.T) {
	e := newSessEnv(t, &fakeLimiter{}, testLimits)
	e.store.writeErr = errors.New("openfga down")

	rec := e.do(http.MethodPost, "/authz/sessions", "gm-bearer", "")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("mint = %d, want 503", rec.Code)
	}
	if e.mints.open("u-gm") != 0 {
		t.Errorf("open mints = %d after a failed write, want 0 (no slot held)", e.mints.open("u-gm"))
	}
}

func TestAuditFailureStopsTheWrite(t *testing.T) {
	e := newSessEnv(t, &fakeLimiter{}, testLimits)
	e.auditE = errors.New("audit store down")

	rec := e.do(http.MethodPost, "/authz/sessions", "gm-bearer", "")

	if rec.Code != http.StatusServiceUnavailable || len(e.store.tuples) != 0 {
		t.Fatalf("mint = %d with tuples %+v; want 503 and nothing written", rec.Code, e.store.tuples)
	}
}

func TestSessionTuplesFollowTheRuleTable(t *testing.T) {
	const id = "0123456789abcdef01234567"
	cases := []struct {
		name, bearer, body string
		want               int
	}{
		{"gm adds a player", "gm-bearer", tuplesBody(id, tup("u-new", "player"), ""), 200},
		{"co_gm adds a player", "co-bearer", tuplesBody(id, tup("u-new", "player"), ""), 200},
		{"co_gm cannot add a co_gm", "co-bearer", tuplesBody(id, tup("u-new", "co_gm"), ""), 403},
		{"co_gm cannot delete a co_gm", "co-bearer", tuplesBody(id, "", tup("u-gm2", "co_gm")), 403},
		{"gm adds a co_gm", "gm-bearer", tuplesBody(id, tup("u-new", "co_gm"), ""), 200},
		{"player cannot add", "player-bearer", tuplesBody(id, tup("u-new", "player"), ""), 403},
		{"player cannot delete another", "player-bearer", tuplesBody(id, "", tup("u-co", "player")), 403},
		{"player leaves", "player-bearer", tuplesBody(id, "", tup("u-pl", "player")), 200},
		{"player cannot leave and add", "player-bearer", tuplesBody(id, tup("u-new", "player"), tup("u-pl", "player")), 403},
		{"outsider cannot write", "out-bearer", tuplesBody(id, tup("u-new", "player"), ""), 403},
		{"outsider cannot delete own tuple that is not theirs", "out-bearer", tuplesBody(id, "", tup("u-out", "player")), 403},
		{"gm tuples are never written", "gm-bearer", tuplesBody(id, tup("u-new", "gm"), ""), 400},
		{"gm tuples are never deleted", "gm-bearer", tuplesBody(id, "", tup("u-gm", "gm")), 400},
		{"unknown relation", "gm-bearer", tuplesBody(id, tup("u-new", "owner"), ""), 400},
		{"login subject instead of a canonical user", "gm-bearer", tuplesBody(id, `{"user":"auth0|x","relation":"player"}`, ""), 400},
		{"empty change", "gm-bearer", tuplesBody(id, "", ""), 400},
		{"malformed session id", "gm-bearer", tuplesBody("SESSION-1", tup("u-new", "player"), ""), 400},
		{"denied user", "denied-bearer", tuplesBody(id, tup("u-new", "player"), ""), 403},
		{"forged token", "forged", tuplesBody(id, tup("u-new", "player"), ""), 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newSessEnv(t, &fakeLimiter{}, testLimits)
			e.seed(id, map[string]string{"u-gm": "gm", "u-co": "co_gm", "u-pl": "player", "u-gm2": "co_gm"})

			rec := e.do(http.MethodPost, "/authz/session-tuples", tc.bearer, tc.body)

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body)
			}
			if tc.want != 200 && e.store.writes != 0 {
				t.Errorf("a refused request wrote to the store")
			}
		})
	}
}

func TestRoleChangeIsOneAtomicWrite(t *testing.T) {
	const id = "0123456789abcdef01234567"
	e := newSessEnv(t, &fakeLimiter{}, testLimits)
	e.seed(id, map[string]string{"u-gm": "gm", "u-ob": "observer"})

	rec := e.do(http.MethodPost, "/authz/session-tuples", "gm-bearer", tuplesBody(id, tup("u-ob", "player"), tup("u-ob", "observer")))

	if rec.Code != 200 || e.store.writes != 1 {
		t.Fatalf("status %d with %d store writes, want 200 and 1", rec.Code, e.store.writes)
	}
	if !e.store.has("user:u-ob", "player", "session:"+id) || e.store.has("user:u-ob", "observer", "session:"+id) {
		t.Errorf("tuples = %+v, want u-ob as player only", e.store.on("session:"+id))
	}
}

func TestSessionTuplesAlwaysLandOnTheSessionObject(t *testing.T) {
	const id = "0123456789abcdef01234567"
	e := newSessEnv(t, &fakeLimiter{}, testLimits)
	e.seed(id, map[string]string{"u-gm": "gm"})
	body := fmt.Sprintf(`{"session_id":%q,"object":"encounter:abc","writes":[%s]}`, id, tup("u-new", "player"))

	rec := e.do(http.MethodPost, "/authz/session-tuples", "gm-bearer", body)

	if rec.Code != 200 || len(e.store.on("encounter:abc")) != 0 || !e.store.has("user:u-new", "player", "session:"+id) {
		t.Fatalf("status %d, tuples %+v; want the player on the session and nothing on the encounter", rec.Code, e.store.tuples)
	}
}

func TestSessionTuplesRefuseAFullSession(t *testing.T) {
	const id = "0123456789abcdef01234567"
	limits := testLimits
	limits.MaxSessionTuples = 3
	e := newSessEnv(t, &fakeLimiter{}, limits)
	e.seed(id, map[string]string{"u-gm": "gm", "u-a": "player", "u-b": "player"})

	rec := e.do(http.MethodPost, "/authz/session-tuples", "gm-bearer", tuplesBody(id, tup("u-c", "player"), ""))

	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "session_full") {
		t.Fatalf("status = %d %s, want 409 session_full", rec.Code, rec.Body)
	}
	swap := e.do(http.MethodPost, "/authz/session-tuples", "gm-bearer", tuplesBody(id, tup("u-c", "player"), tup("u-b", "player")))
	if swap.Code != 200 {
		t.Errorf("a swap at the cap = %d, want 200", swap.Code)
	}
}

func TestSessionTuplesFailClosed(t *testing.T) {
	const id = "0123456789abcdef01234567"
	body := tuplesBody(id, tup("u-new", "player"), "")
	cases := map[string]struct {
		lim    rateChecker
		mutate func(*sessEnv)
	}{
		"check error": {&fakeLimiter{}, func(e *sessEnv) { e.store.checkErr = errors.New("down") }},
		"write error": {&fakeLimiter{}, func(e *sessEnv) { e.store.writeErr = errors.New("down") }},
		"audit error": {&fakeLimiter{}, func(e *sessEnv) { e.auditE = errors.New("down") }},
		"redis down":  {&fakeLimiter{err: errors.New("down")}, func(*sessEnv) {}},
		"no limiter":  {nil, func(*sessEnv) {}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newSessEnv(t, tc.lim, testLimits)
			e.seed(id, map[string]string{"u-gm": "gm"})
			tc.mutate(e)

			rec := e.do(http.MethodPost, "/authz/session-tuples", "gm-bearer", body)

			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503", rec.Code)
			}
			if e.store.has("user:u-new", "player", "session:"+id) {
				t.Errorf("the tuple was written despite %s", name)
			}
		})
	}
}

func TestSessionTuplesAreRateLimited(t *testing.T) {
	const id = "0123456789abcdef01234567"
	e := newSessEnv(t, &fakeLimiter{deny: map[string]bool{tierSessionTups: true}}, testLimits)
	e.seed(id, map[string]string{"u-gm": "gm"})

	rec := e.do(http.MethodPost, "/authz/session-tuples", "gm-bearer", tuplesBody(id, tup("u-new", "player"), ""))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
}

func TestOnlyTheGMEndsASessionAndEveryTupleGoes(t *testing.T) {
	e := newSessEnv(t, &fakeLimiter{}, testLimits)
	id := e.mint(t, "gm-bearer")
	e.seed(id, map[string]string{"u-co": "co_gm", "u-pl": "player"})
	path := "/authz/sessions/" + id

	if rec := e.do(http.MethodDelete, path, "co-bearer", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("co_gm end = %d, want 403", rec.Code)
	}
	if len(e.store.on("session:"+id)) != 3 {
		t.Fatalf("a refused end changed the tuples: %+v", e.store.on("session:"+id))
	}

	rec := e.do(http.MethodDelete, path, "gm-bearer", "")

	if rec.Code != http.StatusNoContent || len(e.store.on("session:"+id)) != 0 {
		t.Fatalf("gm end = %d, tuples %+v; want 204 and none left", rec.Code, e.store.on("session:"+id))
	}
	if e.mints.open("u-gm") != 0 {
		t.Errorf("open mints = %d after ending, want 0", e.mints.open("u-gm"))
	}
	if rec := e.do(http.MethodDelete, "/authz/sessions/NOPE", "gm-bearer", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("bad id = %d, want 400", rec.Code)
	}
}

func TestListMintsFiltersByAuthAPIsOwnClock(t *testing.T) {
	e := newSessEnv(t, &fakeLimiter{}, testLimits)
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	nowFunc = func() time.Time { return now }
	_ = e.mints.Insert(context.Background(), models.SessionMint{ID: "aaaaaaaaaaaaaaaaaaaaaaaa", UserID: "u-gm", CreatedAt: now.Add(-20 * time.Minute)})
	_ = e.mints.Insert(context.Background(), models.SessionMint{ID: "bbbbbbbbbbbbbbbbbbbbbbbb", UserID: "u-gm", CreatedAt: now.Add(-5 * time.Minute)})
	closedAt := now
	_ = e.mints.Insert(context.Background(), models.SessionMint{ID: "cccccccccccccccccccccccc", UserID: "u-gm", CreatedAt: now.Add(-time.Hour), ClosedAt: &closedAt})

	rec := e.do(http.MethodGet, "/internal/openfga/session-mints?min_age=15m", "writer-bearer", "")

	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "aaaaaaaaaaaaaaaaaaaaaaaa") || strings.Contains(body, "bbbbbbbbbbbbbbbbbbbbbbbb") || strings.Contains(body, "cccccccccccccccccccccccc") {
		t.Fatalf("list = %d %s; want only the open mint older than 15m", rec.Code, body)
	}
	for _, bad := range []string{"", "?min_age=junk", "?min_age=-1m", "?min_age=48h", "?min_age=1m&limit=0"} {
		if rec := e.do(http.MethodGet, "/internal/openfga/session-mints"+bad, "writer-bearer", ""); rec.Code != http.StatusBadRequest {
			t.Errorf("list%s = %d, want 400", bad, rec.Code)
		}
	}
}

func TestMintEndpointsNeedTheWriterRole(t *testing.T) {
	e := newSessEnv(t, &fakeLimiter{}, testLimits)
	id := "0123456789abcdef01234567"
	for _, call := range []struct{ method, path string }{
		{http.MethodGet, "/internal/openfga/session-mints?min_age=1m"},
		{http.MethodPost, "/internal/openfga/session-mints/" + id + "/close"},
	} {
		if rec := e.do(call.method, call.path, "gm-bearer", ""); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s as a plain user = %d, want 403", call.method, call.path, rec.Code)
		}
	}
}

func TestCloseMintDeletesEveryPlantedTupleAndIsIdempotent(t *testing.T) {
	e := newSessEnv(t, &fakeLimiter{}, testLimits)
	id := e.mint(t, "gm-bearer")
	e.seed(id, map[string]string{"u-co": "co_gm", "u-pl": "player", "u-ob": "observer"})
	path := "/internal/openfga/session-mints/" + id + "/close"

	first := e.do(http.MethodPost, path, "writer-bearer", "")
	second := e.do(http.MethodPost, path, "writer-bearer", "")

	if first.Code != http.StatusNoContent || second.Code != http.StatusNoContent {
		t.Fatalf("close = %d then %d, want 204 twice", first.Code, second.Code)
	}
	if left := e.store.on("session:" + id); len(left) != 0 {
		t.Fatalf("tuples left after close: %+v (a leftover co_gm keeps can_edit)", left)
	}
	if e.mints.closes != 1 {
		t.Errorf("mint transitioned to closed %d times, want 1 (a double close is a no-op)", e.mints.closes)
	}
	if rec := e.do(http.MethodPost, "/internal/openfga/session-mints/NOPE/close", "writer-bearer", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("bad id = %d, want 400", rec.Code)
	}
}

func TestDeleteAllTuplesPagesThroughLargeSessions(t *testing.T) {
	store := &memStore{}
	for i := range 250 {
		store.tuples = append(store.tuples, fga.Tuple{User: fmt.Sprintf("user:u-%d", i), Relation: "player", Object: "session:x"})
	}

	if err := deleteAllTuples(context.Background(), store, "session:x"); err != nil {
		t.Fatal(err)
	}

	if len(store.on("session:x")) != 0 {
		t.Fatalf("%d tuples left, want 0", len(store.on("session:x")))
	}
}

func TestSessionLimitsDefaultsAndOverrides(t *testing.T) {
	t.Setenv("MAX_OPEN_MINTS", "7")
	t.Setenv("MINTS_PER_USER_HOUR", "not-a-number")

	got := SessionLimitsFromEnv()

	if got.MaxOpenMints != 7 || got.MintsPerUserHour != 20 || got.MaxSessionTuples != 200 || got.MintsGlobalHour != 600 || got.TupleReqsPerMinute != 120 {
		t.Fatalf("limits = %+v, want MaxOpenMints 7 and the PADR-0040 defaults elsewhere", got)
	}
	if tiers := SessionTiers(got); tiers[tierMintGlobal].Limit != 600 || tiers[tierSessionTups].Window != 60 {
		t.Errorf("tiers = %+v", tiers)
	}
}

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sweetrpg/auth-api/auth0"
	"github.com/sweetrpg/auth-api/events"
	"github.com/sweetrpg/auth-api/models"
	"github.com/sweetrpg/common.go/logging"
)

type capture struct {
	mu   sync.Mutex
	got  []string
	fail bool
}

func (c *capture) Publish(_ context.Context, subject, _ string, body []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return errors.New("bus down")
	}
	c.got = append(c.got, subject+" "+string(body))
	return nil
}

// eventRig stubs the store and audit so the handlers run without a database, and captures what is
// published. held and denied set what the store already holds.
func eventRig(t *testing.T, held, denied bool) (*gin.Engine, *capture, *events.Emitter) {
	t.Helper()
	logging.Init()
	gin.SetMode(gin.TestMode)
	stubAdminAuth(t)
	oHas, oIns, oDel, oHasD, oInsD, oDelD, oAud := hasRole, insertRole, deleteRole, hasDenyEntry, insertDenyEntry, deleteDenyEntry, audited
	hasRole = func(context.Context, models.Principal, models.Role) (bool, error) { return held, nil }
	insertRole = func(context.Context, models.Principal, models.Role, string) error { return nil }
	deleteRole = func(context.Context, models.Principal, models.Role) error { return nil }
	hasDenyEntry = func(context.Context, models.Principal, string) (bool, error) { return denied, nil }
	insertDenyEntry = func(context.Context, models.Principal, string, string) error { return nil }
	deleteDenyEntry = func(context.Context, models.Principal, string) error { return nil }
	audited = func(ctx context.Context, _, _, _, _ string, op func(context.Context) (int, error)) (int, error) {
		return op(ctx)
	}
	cap := &capture{}
	em := events.NewEmitter(cap, []time.Duration{time.Millisecond})
	origEm := eventEmitter
	SetEventEmitter(em)
	t.Cleanup(func() {
		hasRole, insertRole, deleteRole, hasDenyEntry, insertDenyEntry, deleteDenyEntry, audited = oHas, oIns, oDel, oHasD, oInsD, oDelD, oAud
		eventEmitter = origEm
	})
	r := gin.New()
	setupRolesHandlers(r, auth0.NewJWKSCache(), auth0.Config{Domain: "test.auth0.dev", Audience: "test-audience"})
	return r, cap, em
}

func adminReq(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return withBearer(req, adminBearer)
}

func TestDenyPublishesEvent(t *testing.T) {
	r, cap, em := eventRig(t, false, false)
	rec := serve(r, adminReq("POST", "/api/admin/deny-entries/auth0|victim", `{"service":"catalog-api"}`))
	em.Wait()
	if rec.Code != http.StatusCreated || len(cap.got) != 1 ||
		!strings.Contains(cap.got[0], `"entity_id":"auth0|victim"`) || !strings.Contains(cap.got[0], `"action":"deny"`) {
		t.Fatalf("status %d, published %v", rec.Code, cap.got)
	}
}

func TestDenyAlreadyPresentPublishesNothing(t *testing.T) {
	r, cap, em := eventRig(t, false, true)
	rec := serve(r, adminReq("POST", "/api/admin/deny-entries/auth0|victim", `{"service":"catalog-api"}`))
	em.Wait()
	if rec.Code != http.StatusNoContent || len(cap.got) != 0 {
		t.Fatalf("status %d, published %v", rec.Code, cap.got)
	}
}

func TestRoleRemovalPublishesEvent(t *testing.T) {
	r, cap, em := eventRig(t, true, false)
	rec := serve(r, adminReq("DELETE", "/api/admin/roles/auth0|victim/editor", ""))
	em.Wait()
	if rec.Code != http.StatusNoContent || len(cap.got) != 1 || !strings.Contains(cap.got[0], `"action":"role_removed"`) {
		t.Fatalf("status %d, published %v", rec.Code, cap.got)
	}
}

func TestRoleRemovalOfRoleNotHeldPublishesNothing(t *testing.T) {
	r, cap, em := eventRig(t, false, false)
	rec := serve(r, adminReq("DELETE", "/api/admin/roles/auth0|victim/editor", ""))
	em.Wait()
	if rec.Code != http.StatusNoContent || len(cap.got) != 0 {
		t.Fatalf("status %d, published %v", rec.Code, cap.got)
	}
}

func TestFailedPublishDoesNotFailTheAdminRequest(t *testing.T) {
	r, cap, em := eventRig(t, false, false)
	cap.fail = true
	rec := serve(r, adminReq("POST", "/api/admin/deny-entries/auth0|victim", `{"service":"catalog-api"}`))
	em.Wait()
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 even though the bus is down", rec.Code)
	}
}

func TestRoleAddAndDenyRemovalPublishNothing(t *testing.T) {
	r, cap, em := eventRig(t, false, true)
	serve(r, adminReq("POST", "/api/admin/roles/auth0|u", `{"role":"editor"}`))
	serve(r, adminReq("DELETE", "/api/admin/deny-entries/auth0|u/catalog-api", ""))
	em.Wait()
	if len(cap.got) != 0 {
		t.Fatalf("published %v", cap.got)
	}
}

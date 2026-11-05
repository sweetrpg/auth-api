package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sweetrpg/auth-api/registry"
)

func TestListServicesReturnsTheRegistry(t *testing.T) {
	stubAdminAuth(t)
	r := newDenyStatsRouter(t)
	rec := serve(r, withBearer(httptest.NewRequest(http.MethodGet, "/api/admin/services", nil), adminBearer))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	var got []registry.Service
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != len(registry.Services()) || got[0].ID == "" || got[0].Name == "" {
		t.Errorf("body = %s", rec.Body)
	}
}

func TestListServicesNeedsCredentials(t *testing.T) {
	stubAdminAuth(t)
	r := newDenyStatsRouter(t)
	if rec := serve(r, httptest.NewRequest(http.MethodGet, "/api/admin/services", nil)); rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if rec := serve(r, withBearer(httptest.NewRequest(http.MethodGet, "/api/admin/services", nil), userBearer)); rec.Code != http.StatusForbidden {
		t.Errorf("non-admin: status = %d, want 403", rec.Code)
	}
}

func TestDenyEntryForAnUnknownServiceIsRejectedBeforeAnyWrite(t *testing.T) {
	stubAdminAuth(t)
	r := newDenyStatsRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/deny-entries/auth0%7Cabc", strings.NewReader(`{"service":"catalog-apii"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := serve(r, withBearer(req, adminBearer))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"unknown_service"`) {
		t.Errorf("status = %d, body %s", rec.Code, rec.Body)
	}
}

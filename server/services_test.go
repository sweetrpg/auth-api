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
	t.Setenv("INTERNAL_SERVICE_TOKEN", "test-internal-token")
	r := newDenyStatsRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/admin/services", nil)
	req.Header.Set(internalServiceTokenHeader, "test-internal-token")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	var got []registry.Service
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != len(registry.Services()) || got[0].ID == "" || got[0].Name == "" {
		t.Errorf("body = %s", rec.Body)
	}
}

func TestListServicesNeedsCredentials(t *testing.T) {
	r := newDenyStatsRouter(t)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/admin/services", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestDenyEntryForAnUnknownServiceIsRejectedBeforeAnyWrite(t *testing.T) {
	t.Setenv("INTERNAL_SERVICE_TOKEN", "test-internal-token")
	r := newDenyStatsRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/deny-entries/auth0%7Cabc", strings.NewReader(`{"service":"catalog-apii"}`))
	req.Header.Set(internalServiceTokenHeader, "test-internal-token")
	req.Header.Set(actingUserSubHeader, "auth0|admin")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"unknown_service"`) {
		t.Errorf("status = %d, body %s", rec.Code, rec.Body)
	}
}

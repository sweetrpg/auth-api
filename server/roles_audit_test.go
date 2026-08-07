package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sweetrpg/auth-api/auth0"
	"github.com/sweetrpg/auth-api/models"
	"github.com/sweetrpg/common.go/logging"
)

// TestMissingActingUserSubIsRejectedBeforeAnyDatabaseAccess and
// TestMismatchedInternalTokenIsUnauthorizedBeforeAnyDatabaseAccess port
// RolesControllerAuditTests.swift: verifyAdminRole requires
// X-Acting-User-Sub for internal-service-token callers before it ever
// reaches a query or an audit-log write, and rejects a mismatched token -
// neither case touches the database, so these run without one.
func TestMissingActingUserSubIsRejectedBeforeAnyDatabaseAccess(t *testing.T) {
	t.Setenv("INTERNAL_SERVICE_TOKEN", "test-internal-token")
	logging.Init()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	cache := auth0.NewJWKSCache()
	config := auth0.Config{Domain: "test.auth0.dev", Audience: "test-audience"}
	setupRolesHandlers(r, cache, config)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/roles/auth0%7Cabc123", strings.NewReader(`{"role":"admin"}`))
	req.Header.Set(internalServiceTokenHeader, "test-internal-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestMismatchedInternalTokenIsUnauthorizedBeforeAnyDatabaseAccess(t *testing.T) {
	t.Setenv("INTERNAL_SERVICE_TOKEN", "test-internal-token")
	logging.Init()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	cache := auth0.NewJWKSCache()
	config := auth0.Config{Domain: "test.auth0.dev", Audience: "test-audience"}
	setupRolesHandlers(r, cache, config)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/roles/auth0%7Cabc123", strings.NewReader(`{"role":"admin"}`))
	req.Header.Set(internalServiceTokenHeader, "wrong-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestPerformAuditedRefusesOperationWhenAuditWriteFails verifies the
// fail-closed contract design.md calls out as security-critical: if the
// "before" audit write fails, operation must never run. Written before
// server/roles.go's handlers were wired up, per design.md's mitigation for
// this risk.
func TestPerformAuditedRefusesOperationWhenAuditWriteFails(t *testing.T) {
	operationCalled := false
	recordAttempt := func(ctx context.Context, actingUserSub, action, targetSubject, detail string) (uuid.UUID, error) {
		return uuid.UUID{}, errors.New("simulated audit write failure")
	}
	complete := func(ctx context.Context, id uuid.UUID, status models.AuditStatus, errMessage string) error {
		t.Fatal("complete() must not be called when recordAttempt() fails")
		return nil
	}

	_, err := performAuditedWith(context.Background(), "auth0|admin", "add_role", "auth0|target", "admin",
		func(ctx context.Context) (int, error) {
			operationCalled = true
			return http.StatusCreated, nil
		},
		recordAttempt, complete,
	)

	if err == nil {
		t.Fatal("performAuditedWith() error = nil, want an error when the audit write fails")
	}
	if operationCalled {
		t.Error("operation was called despite the audit write failing - fail-closed contract violated")
	}
}

// TestPerformAuditedRunsOperationWhenAuditWriteSucceeds is the positive
// counterpart: a successful audit write must still let the operation run
// and its result flow back to the caller.
func TestPerformAuditedRunsOperationWhenAuditWriteSucceeds(t *testing.T) {
	var completedStatus models.AuditStatus
	recordAttempt := func(ctx context.Context, actingUserSub, action, targetSubject, detail string) (uuid.UUID, error) {
		return uuid.New(), nil
	}
	complete := func(ctx context.Context, id uuid.UUID, status models.AuditStatus, errMessage string) error {
		completedStatus = status
		return nil
	}

	status, err := performAuditedWith(context.Background(), "auth0|admin", "add_role", "auth0|target", "admin",
		func(ctx context.Context) (int, error) {
			return http.StatusCreated, nil
		},
		recordAttempt, complete,
	)

	if err != nil {
		t.Fatalf("performAuditedWith() error = %v", err)
	}
	if status != http.StatusCreated {
		t.Errorf("status = %d, want %d", status, http.StatusCreated)
	}
	if completedStatus != models.AuditSucceeded {
		t.Errorf("completedStatus = %q, want %q", completedStatus, models.AuditSucceeded)
	}
}

// TestPerformAuditedRecordsFailureWhenOperationFails confirms a failing
// operation still gets a "failed" completion record, not a silently
// abandoned "attempted" one.
func TestPerformAuditedRecordsFailureWhenOperationFails(t *testing.T) {
	var completedStatus models.AuditStatus
	recordAttempt := func(ctx context.Context, actingUserSub, action, targetSubject, detail string) (uuid.UUID, error) {
		return uuid.New(), nil
	}
	complete := func(ctx context.Context, id uuid.UUID, status models.AuditStatus, errMessage string) error {
		completedStatus = status
		return nil
	}

	_, err := performAuditedWith(context.Background(), "auth0|admin", "add_role", "auth0|target", "admin",
		func(ctx context.Context) (int, error) {
			return 0, errors.New("operation failed")
		},
		recordAttempt, complete,
	)

	if err == nil {
		t.Fatal("performAuditedWith() error = nil, want the operation's error")
	}
	if completedStatus != models.AuditFailed {
		t.Errorf("completedStatus = %q, want %q", completedStatus, models.AuditFailed)
	}
}

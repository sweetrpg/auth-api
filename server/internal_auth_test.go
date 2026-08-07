package server

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func newTestContext(headers map[string]string) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest("GET", "/", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	c.Request = req
	return c
}

func TestMatchingInternalTokenIsValid(t *testing.T) {
	t.Setenv("INTERNAL_SERVICE_TOKEN", "expected-secret")
	c := newTestContext(map[string]string{internalServiceTokenHeader: "expected-secret"})

	if !hasValidInternalServiceToken(c) {
		t.Error("hasValidInternalServiceToken() = false, want true")
	}
}

func TestMismatchedInternalTokenIsInvalid(t *testing.T) {
	t.Setenv("INTERNAL_SERVICE_TOKEN", "expected-secret")
	c := newTestContext(map[string]string{internalServiceTokenHeader: "wrong-secret"})

	if hasValidInternalServiceToken(c) {
		t.Error("hasValidInternalServiceToken() = true, want false")
	}
}

func TestMissingInternalTokenHeaderIsInvalid(t *testing.T) {
	t.Setenv("INTERNAL_SERVICE_TOKEN", "expected-secret")
	c := newTestContext(nil)

	if hasValidInternalServiceToken(c) {
		t.Error("hasValidInternalServiceToken() = true, want false")
	}
}

func TestInternalTokenDisabledWhenUnset(t *testing.T) {
	t.Setenv("INTERNAL_SERVICE_TOKEN", "")
	c := newTestContext(map[string]string{internalServiceTokenHeader: "anything"})

	if hasValidInternalServiceToken(c) {
		t.Error("hasValidInternalServiceToken() = true, want false")
	}
}

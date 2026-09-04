package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sweetrpg/common.go/logging"
)

func newRateLimiterTestRouter(t *testing.T, ratePerSecond, burst string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	logging.Init() // RateLimiter logs through the package-level Logger on 429
	t.Setenv("RATE_LIMIT_PER_SECOND", ratePerSecond)
	t.Setenv("RATE_LIMIT", burst)

	r := gin.New()
	r.Use(RateLimiter())
	r.GET("/status/ping", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/status/health", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/authz/check", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func doGet(r *gin.Engine, path, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestRateLimiterExemptsHealthPaths(t *testing.T) {
	r := newRateLimiterTestRouter(t, "1", "1")
	for i := 0; i < 5; i++ {
		if rec := doGet(r, "/status/ping", "10.0.0.1:1111"); rec.Code != http.StatusOK {
			t.Fatalf("ping #%d status = %d, want 200 (health paths must never be rate limited)", i, rec.Code)
		}
		if rec := doGet(r, "/status/health", "10.0.0.1:1111"); rec.Code != http.StatusOK {
			t.Fatalf("health #%d status = %d, want 200", i, rec.Code)
		}
	}
}

func TestRateLimiterBlocksAfterBurstForSameCaller(t *testing.T) {
	r := newRateLimiterTestRouter(t, "1", "2")

	for i := 0; i < 2; i++ {
		if rec := doGet(r, "/authz/check", "10.0.0.2:1111"); rec.Code != http.StatusOK {
			t.Fatalf("request #%d status = %d, want 200 (within burst)", i, rec.Code)
		}
	}
	rec := doGet(r, "/authz/check", "10.0.0.2:1111")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 once the burst is exhausted", rec.Code)
	}
}

func TestRateLimiterIsolatesCallersByIP(t *testing.T) {
	r := newRateLimiterTestRouter(t, "1", "1")

	if rec := doGet(r, "/authz/check", "10.0.0.3:1111"); rec.Code != http.StatusOK {
		t.Fatalf("caller A first request status = %d, want 200", rec.Code)
	}
	if rec := doGet(r, "/authz/check", "10.0.0.3:1111"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("caller A second request status = %d, want 429 (burst exhausted)", rec.Code)
	}
	// A different caller IP must have its own budget, unaffected by A's.
	if rec := doGet(r, "/authz/check", "10.0.0.4:1111"); rec.Code != http.StatusOK {
		t.Fatalf("caller B status = %d, want 200 (separate budget from caller A)", rec.Code)
	}
}

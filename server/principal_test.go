package server

import (
	"context"
	"testing"

	"github.com/sweetrpg/auth-api/identity"
)

func TestOwnPrincipalUsesTheCallersBearerAndCachedPrincipalNeverCallsOut(t *testing.T) {
	calls := 0
	userResolver = identity.New("", func(_ context.Context, token string) string {
		calls++
		if token == "user-token" {
			return "user-1"
		}
		return ""
	})
	t.Cleanup(func() { userResolver = nil })

	if p := cachedPrincipal("auth0|a"); p.UserID != "" || calls != 0 {
		t.Fatalf("cached before any lookup: %+v after %d calls", p, calls)
	}
	if p := ownPrincipal(context.Background(), "auth0|a", "user-token"); p.UserID != "user-1" || p.Subject != "auth0|a" {
		t.Fatalf("own = %+v", p)
	}
	if p := cachedPrincipal("auth0|a"); p.UserID != "user-1" || calls != 1 {
		t.Errorf("cached after lookup: %+v, %d calls", p, calls)
	}
}

func TestTargetPrincipalWithoutAnAdminBearerKeepsTheSubjectAlone(t *testing.T) {
	userResolver = identity.New("http://unused.invalid", nil)
	t.Cleanup(func() { userResolver = nil })
	if p := targetPrincipal(context.Background(), "auth0|b", ""); p.UserID != "" || p.Subject != "auth0|b" {
		t.Errorf("target = %+v", p)
	}
}

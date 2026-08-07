package auth0

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var testConfig = Config{Domain: "test.auth0.dev", Audience: "test-audience"}

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test RSA key: %v", err)
	}
	return key
}

func jwksJSON(pub *rsa.PublicKey, kid string) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","use":"sig","kid":%q,"n":%q,"e":%q}]}`, kid, n, e)
}

type tokenOpts struct {
	kid        string
	subject    string
	expiration time.Time
	issuer     string
	audience   string
}

func signedToken(t *testing.T, key *rsa.PrivateKey, opts tokenOpts) string {
	t.Helper()
	if opts.subject == "" {
		opts.subject = "auth0|abc123"
	}
	if opts.expiration.IsZero() {
		opts.expiration = time.Now().Add(time.Hour)
	}
	if opts.issuer == "" {
		opts.issuer = testConfig.Issuer()
	}
	if opts.audience == "" {
		opts.audience = testConfig.Audience
	}

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   opts.subject,
			ExpiresAt: jwt.NewNumericDate(opts.expiration),
			Issuer:    opts.issuer,
			Audience:  jwt.ClaimStrings{opts.audience},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = opts.kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign test token: %v", err)
	}
	return signed
}

// stubJWKSServer returns a fixed JWKS response for every request, tracking
// how many times it was called - mirrors JWKSCacheTests.swift's StubClient.
type stubJWKSServer struct {
	*httptest.Server
	callCount int
	kid       string
	pub       *rsa.PublicKey
}

func newStubJWKSServer(kid string, pub *rsa.PublicKey) *stubJWKSServer {
	s := &stubJWKSServer{kid: kid, pub: pub}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.callCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwksJSON(s.pub, s.kid)))
	}))
	return s
}

func newCache(server *stubJWKSServer) *JWKSCache {
	c := NewJWKSCache()
	c.JWKSURLOverride = server.URL
	return c
}

func TestVerifySucceedsOnFirstFetch(t *testing.T) {
	key := generateTestKey(t)
	server := newStubJWKSServer("key-1", &key.PublicKey)
	defer server.Close()

	token := signedToken(t, key, tokenOpts{kid: "key-1"})

	claims, err := newCache(server).Verify(context.Background(), token, testConfig)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims.Subject != "auth0|abc123" {
		t.Errorf("Subject = %q, want auth0|abc123", claims.Subject)
	}
	if server.callCount != 1 {
		t.Errorf("callCount = %d, want 1", server.callCount)
	}
}

func TestSecondVerifyUsesCacheWithoutRefetching(t *testing.T) {
	key := generateTestKey(t)
	server := newStubJWKSServer("key-1", &key.PublicKey)
	defer server.Close()

	cache := newCache(server)
	token := signedToken(t, key, tokenOpts{kid: "key-1"})

	if _, err := cache.Verify(context.Background(), token, testConfig); err != nil {
		t.Fatalf("first Verify() error = %v", err)
	}
	if _, err := cache.Verify(context.Background(), token, testConfig); err != nil {
		t.Fatalf("second Verify() error = %v", err)
	}

	if server.callCount != 1 {
		t.Errorf("callCount = %d, want 1", server.callCount)
	}
}

func TestUnknownKIDTriggersExactlyOneRefetch(t *testing.T) {
	key := generateTestKey(t)
	server := newStubJWKSServer("key-1", &key.PublicKey)
	defer server.Close()

	cache := newCache(server)

	// Prime the cache with a JWKS that doesn't contain "key-2".
	if _, err := cache.Verify(context.Background(), signedToken(t, key, tokenOpts{kid: "key-1"}), testConfig); err != nil {
		t.Fatalf("priming Verify() error = %v", err)
	}
	if server.callCount != 1 {
		t.Fatalf("callCount after priming = %d, want 1", server.callCount)
	}

	// Simulate Auth0 rotating to a new key: the stub now serves "key-2".
	server.kid = "key-2"
	claims, err := cache.Verify(context.Background(), signedToken(t, key, tokenOpts{kid: "key-2"}), testConfig)
	if err != nil {
		t.Fatalf("Verify() after rotation error = %v", err)
	}
	if claims.Subject != "auth0|abc123" {
		t.Errorf("Subject = %q, want auth0|abc123", claims.Subject)
	}
	if server.callCount != 2 {
		t.Errorf("callCount = %d, want 2", server.callCount)
	}
}

func TestUnknownKIDStillMissingAfterRefetchFails(t *testing.T) {
	key := generateTestKey(t)
	server := newStubJWKSServer("key-1", &key.PublicKey)
	defer server.Close()

	cache := newCache(server)
	token := signedToken(t, key, tokenOpts{kid: "key-does-not-exist"})

	if _, err := cache.Verify(context.Background(), token, testConfig); err == nil {
		t.Fatal("Verify() error = nil, want an unknown-kid error")
	}
	if server.callCount != 1 {
		t.Errorf("callCount = %d, want 1 (exactly one refetch attempt for an unresolvable kid)", server.callCount)
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	key := generateTestKey(t)
	server := newStubJWKSServer("key-1", &key.PublicKey)
	defer server.Close()

	token := signedToken(t, key, tokenOpts{kid: "key-1", expiration: time.Now().Add(-time.Hour)})

	if _, err := newCache(server).Verify(context.Background(), token, testConfig); err == nil {
		t.Fatal("Verify() error = nil, want an expiration error")
	}
}

func TestWrongAudienceIsRejected(t *testing.T) {
	key := generateTestKey(t)
	server := newStubJWKSServer("key-1", &key.PublicKey)
	defer server.Close()

	token := signedToken(t, key, tokenOpts{kid: "key-1", audience: "someone-elses-audience"})

	if _, err := newCache(server).Verify(context.Background(), token, testConfig); err == nil {
		t.Fatal("Verify() error = nil, want an audience error")
	}
}

func TestWrongIssuerIsRejected(t *testing.T) {
	key := generateTestKey(t)
	server := newStubJWKSServer("key-1", &key.PublicKey)
	defer server.Close()

	token := signedToken(t, key, tokenOpts{kid: "key-1", issuer: "https://not-our-tenant.auth0.com/"})

	if _, err := newCache(server).Verify(context.Background(), token, testConfig); err == nil {
		t.Fatal("Verify() error = nil, want an issuer error")
	}
}

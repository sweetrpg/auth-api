package auth0

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// JWKSCache fetches and caches an Auth0 tenant's JWKS. A verification
// attempt against a kid not in the cache triggers exactly one refetch
// (Auth0 rotates signing keys occasionally; a cache built before a rotation
// shouldn't reject a token signed with the new key) before failing as
// invalid. Ports the Swift service's JWKSCache 1:1 - see jwks_cache_test.go
// for the refetch-once behavior this guarantees.
type JWKSCache struct {
	httpClient *http.Client

	// JWKSURLOverride, when set, is fetched instead of config.JWKSURL() - a
	// seam for tests to point the cache at a local stub server rather than a
	// real Auth0 tenant.
	JWKSURLOverride string

	mu sync.RWMutex
	kf keyfunc.Keyfunc
}

// NewJWKSCache returns an empty cache; the first Verify call populates it.
func NewJWKSCache() *JWKSCache {
	return &JWKSCache{httpClient: &http.Client{Timeout: 10 * time.Second}}
}

func (c *JWKSCache) cached() keyfunc.Keyfunc {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.kf
}

func (c *JWKSCache) store(kf keyfunc.Keyfunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kf = kf
}

func (c *JWKSCache) fetch(ctx context.Context, config Config) (keyfunc.Keyfunc, error) {
	url := config.JWKSURL()
	if c.JWKSURLOverride != "" {
		url = c.JWKSURLOverride
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Auth0 JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch Auth0 JWKS: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Auth0 JWKS response: %w", err)
	}

	kf, err := keyfunc.NewJWKSetJSON(json.RawMessage(body))
	if err != nil {
		return nil, fmt.Errorf("failed to parse Auth0 JWKS: %w", err)
	}
	c.store(kf)
	return kf, nil
}

// Verify verifies token against Auth0's JWKS. It checks the token's kid
// against the current cache *before* parsing (matching the Swift service's
// membership check, not a parse-then-retry loop): a kid already present
// uses the cache with no HTTP call; a kid missing (or no cache fetched yet)
// triggers exactly one fetch, after which the kid is either present or the
// token is rejected - never a second fetch for the same Verify call, since
// a kid genuinely absent from the tenant's JWKS won't appear on a retry.
func (c *JWKSCache) Verify(ctx context.Context, token string, config Config) (*Claims, error) {
	kid, err := extractKID(token)
	if err != nil {
		return nil, err
	}

	kf := c.cached()
	if kf == nil || !c.hasKID(ctx, kf, kid) {
		kf, err = c.fetch(ctx, config)
		if err != nil {
			return nil, err
		}
	}

	return c.parse(token, kf, config)
}

func (c *JWKSCache) hasKID(ctx context.Context, kf keyfunc.Keyfunc, kid string) bool {
	_, err := kf.Storage().KeyRead(ctx, kid)
	return err == nil
}

func extractKID(token string) (string, error) {
	unverified := &Claims{}
	parsed, _, err := jwt.NewParser().ParseUnverified(token, unverified)
	if err != nil {
		return "", fmt.Errorf("failed to parse token header: %w", err)
	}
	kid, ok := parsed.Header["kid"].(string)
	if !ok || kid == "" {
		return "", jwt.ErrTokenMalformed
	}
	return kid, nil
}

func (c *JWKSCache) parse(token string, kf keyfunc.Keyfunc, config Config) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(token, claims, kf.Keyfunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(config.Issuer()),
		jwt.WithAudience(config.Audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

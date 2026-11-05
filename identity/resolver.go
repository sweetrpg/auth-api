// Package identity maps an Auth0 subject to the canonical user it belongs to, so roles and
// deny entries follow the person across their linked logins. Every lookup uses a real user's
// bearer token (PADR-0037): the caller's own for their own subject, an administrator's for
// someone else's. There is no service credential.
package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/sweetrpg/common.go/logging"
)

const (
	foundTTL    = time.Minute
	notFoundTTL = 10 * time.Second
	maxBatch    = 200
)

// OwnLookup resolves the canonical user ID of the bearer token's own user (users-api GET
// /profile); "" when it cannot.
type OwnLookup func(ctx context.Context, token string) string

// Resolver caches subject -> canonical user answers briefly because /authz/check asks on every
// request. A failed or impossible lookup reports "" so callers fall back to the subject alone.
type Resolver struct {
	baseURL string
	own     OwnLookup
	http    *http.Client
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]entry
}

type entry struct {
	userID  string
	expires time.Time
}

// New returns a Resolver. baseURL is users-api's; own looks up a caller's own user.
func New(baseURL string, own OwnLookup) *Resolver {
	return &Resolver{baseURL: baseURL, own: own, http: &http.Client{Timeout: 3 * time.Second}, now: time.Now, cache: map[string]entry{}}
}

// Cached returns a fresh cached answer for subject without any network call.
func (r *Resolver) Cached(subject string) string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.cache[subject]; ok && r.now().Before(e.expires) {
		return e.userID
	}
	return ""
}

// Own returns the canonical user of the caller whose verified subject is subject, looked up with
// the caller's own bearer token. "" when the token is missing or the lookup fails.
func (r *Resolver) Own(ctx context.Context, subject, token string) string {
	if r == nil || subject == "" || token == "" {
		return ""
	}
	if e, ok := r.entry(subject); ok {
		return e.userID
	}
	id := ""
	if r.own != nil {
		id = r.own(ctx, token)
	}
	r.store(subject, id)
	return id
}

// Other returns the canonical user of someone else's subject, looked up with an administrator's
// bearer token. "" when there is no admin token (a caller using another credential) or the
// lookup fails, with a WARN so the gap is visible.
func (r *Resolver) Other(ctx context.Context, subject, adminToken string) string {
	if r == nil || subject == "" {
		return ""
	}
	if e, ok := r.entry(subject); ok {
		return e.userID
	}
	if adminToken == "" {
		logging.Logger.Warn("no admin bearer token to resolve the subject's canonical user; using the subject alone", "subject", subject)
		return ""
	}
	resolved, err := r.Resolve(ctx, []string{subject}, adminToken)
	if err != nil {
		logging.Logger.Warn("could not resolve the subject's canonical user; using the subject alone", "subject", subject, "error", err.Error())
		return ""
	}
	r.store(subject, resolved[subject])
	return resolved[subject]
}

// Resolve maps subjects to canonical user IDs through users-api's POST /internal/resolve-subjects,
// authorized by an administrator's bearer token. Subjects with no user are absent from the result.
func (r *Resolver) Resolve(ctx context.Context, subjects []string, adminToken string) (map[string]string, error) {
	if r == nil || r.baseURL == "" {
		return nil, fmt.Errorf("USERS_API_URL is not configured")
	}
	if adminToken == "" {
		return nil, fmt.Errorf("an administrator bearer token is required")
	}
	out := map[string]string{}
	for start := 0; start < len(subjects); start += maxBatch {
		batch := subjects[start:min(start+maxBatch, len(subjects))]
		body, err := json.Marshal(map[string][]string{"subjects": batch})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+"/internal/resolve-subjects", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := r.http.Do(req)
		if err != nil {
			return nil, err
		}
		var part map[string]string
		if err := decode(resp, &part); err != nil {
			return nil, err
		}
		for k, v := range part {
			out[k] = v
		}
	}
	return out, nil
}

func decode(resp *http.Response, v any) error {
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("users-api answered %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func (r *Resolver) entry(subject string) (entry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[subject]
	if !ok || !r.now().Before(e.expires) {
		return entry{}, false
	}
	return e, true
}

func (r *Resolver) store(subject, userID string) {
	ttl := foundTTL
	if userID == "" {
		ttl = notFoundTTL
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[subject] = entry{userID: userID, expires: r.now().Add(ttl)}
}

// Package identity maps an Auth0 subject to the canonical user it belongs to, so roles and
// deny entries follow the person across their linked logins.
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

// Resolver asks users-api (POST /internal/resolve-subjects, shared internal token) for the
// canonical user ID of a subject, caching answers briefly because /authz/check calls it on every
// request. A lookup that fails reports "" so callers fall back to the subject alone.
type Resolver struct {
	baseURL string
	token   string
	http    *http.Client
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]entry
}

type entry struct {
	userID  string
	expires time.Time
}

// New returns a Resolver. With an empty baseURL or token every lookup reports "".
func New(baseURL, token string) *Resolver {
	return &Resolver{
		baseURL: baseURL, token: token, http: &http.Client{Timeout: 3 * time.Second},
		now: time.Now, cache: map[string]entry{},
	}
}

// UserID returns the canonical user ID for subject, or "" when unknown or unavailable.
func (r *Resolver) UserID(ctx context.Context, subject string) string {
	if r == nil || subject == "" {
		return ""
	}
	if id, ok := r.cached(subject); ok {
		return id
	}
	resolved, err := r.Resolve(ctx, []string{subject})
	if err != nil {
		logging.Logger.Warn("could not resolve the subject's canonical user; using the subject alone", "subject", subject, "error", err.Error())
		return ""
	}
	r.store(subject, resolved[subject])
	return resolved[subject]
}

// Resolve maps subjects to canonical user IDs; subjects with no user are absent from the result.
func (r *Resolver) Resolve(ctx context.Context, subjects []string) (map[string]string, error) {
	if r == nil || r.baseURL == "" || r.token == "" {
		return nil, fmt.Errorf("users-api resolver not configured (USERS_API_URL and INTERNAL_SERVICE_TOKEN)")
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
		req.Header.Set("X-Internal-Service-Token", r.token)
		resp, err := r.http.Do(req)
		if err != nil {
			return nil, err
		}
		var part map[string]string
		err = decode(resp, &part)
		if err != nil {
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

func (r *Resolver) cached(subject string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[subject]
	if !ok || !r.now().Before(e.expires) {
		return "", false
	}
	return e.userID, true
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

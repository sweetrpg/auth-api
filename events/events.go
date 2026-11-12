// Package events publishes auth-api's deny and role-removal changes to the platform bus
// (PADR-0039) so services holding long-lived credentials for a subject can revoke them. An event
// carries the Auth0 subject and the change kind; it carries no token (PADR-0037).
package events

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Change kinds, the envelope's action.
const (
	KindDeny        = "deny"
	KindRoleRemoved = "role_removed"
)

// SubjectPrefix starts every event subject: auth.events.<subject token>.
const SubjectPrefix = "auth.events."

// Event is the platform envelope. EntityID is the Auth0 subject. Data.Service names the denied
// service for a deny.
type Event struct {
	EventID    string    `json:"event_id"`
	OccurredAt time.Time `json:"occurred_at"`
	Source     string    `json:"source"`
	EntityType string    `json:"entity_type"`
	EntityID   string    `json:"entity_id"`
	Action     string    `json:"action"`
	Data       EventData `json:"data"`
}

// EventData is the kind-specific detail.
type EventData struct {
	Service string `json:"service,omitempty"`
	Role    string `json:"role,omitempty"`
}

// Publisher puts one message on the bus. msgID lets the bus drop a redelivered duplicate.
type Publisher interface {
	Publish(ctx context.Context, subject, msgID string, body []byte) error
}

// SubjectFor is the event subject for an Auth0 subject. NATS tokens cannot hold '.', '*', '>' or
// whitespace, and Auth0 subjects can (email-based connections), so those become '_'. The real
// subject travels in entity_id.
func SubjectFor(subject string) string {
	return SubjectPrefix + strings.Map(func(r rune) rune {
		switch r {
		case '.', '*', '>', ' ', '\t', '\n', '\r':
			return '_'
		}
		return r
	}, subject)
}

// Emitter publishes events after the change that caused them committed. A failed publish is
// retried with backoff in the background and never fails the admin request.
type Emitter struct {
	pub     Publisher
	backoff []time.Duration
	wg      sync.WaitGroup
}

// DefaultBackoff is the wait before each retry; after the last the event is dropped and logged.
var DefaultBackoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}

// NewEmitter builds an Emitter. A nil pub drops events with a warning, for deployments with no bus.
func NewEmitter(pub Publisher, backoff []time.Duration) *Emitter {
	return &Emitter{pub: pub, backoff: backoff}
}

// Emit publishes one change for subject without blocking the caller.
func (e *Emitter) Emit(kind, subject string, data EventData) {
	ev := Event{EventID: uuid.NewString(), OccurredAt: time.Now().UTC(), Source: "auth-api", EntityType: "subject", EntityID: subject, Action: kind, Data: data}
	if e == nil || e.pub == nil {
		slog.Warn("auth event not published: no event bus configured", "event_id", ev.EventID, "action", kind)
		return
	}
	body, err := json.Marshal(ev)
	if err != nil {
		slog.Error("auth event not published: marshal failed", "event_id", ev.EventID, "error", err)
		return
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.send(ev, body)
	}()
}

func (e *Emitter) send(ev Event, body []byte) {
	var err error
	for attempt := 0; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = e.pub.Publish(ctx, SubjectFor(ev.EntityID), ev.EventID, body)
		cancel()
		if err == nil {
			return
		}
		if attempt >= len(e.backoff) {
			break
		}
		slog.Warn("auth event publish failed, retrying", "event_id", ev.EventID, "action", ev.Action, "attempt", attempt+1, "error", err)
		time.Sleep(e.backoff[attempt])
	}
	slog.Error(fmt.Sprintf("auth event dropped after %d retries; the subject's integration credentials are not revoked until reconciled", len(e.backoff)),
		"event_id", ev.EventID, "action", ev.Action, "error", err)
}

// Wait blocks until every in-flight publish has finished or been dropped.
func (e *Emitter) Wait() { e.wg.Wait() }

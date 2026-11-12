package events

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakePub struct {
	mu      sync.Mutex
	failFor int
	calls   int
	subject string
	msgID   string
	body    []byte
}

func (f *fakePub) Publish(_ context.Context, subject, msgID string, body []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failFor {
		return errors.New("bus down")
	}
	f.subject, f.msgID, f.body = subject, msgID, body
	return nil
}

var fast = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}

func TestEmitPublishesEnvelope(t *testing.T) {
	p := &fakePub{}
	e := NewEmitter(p, fast)
	e.Emit(KindDeny, "auth0|abc", EventData{Service: "catalog-api"})
	e.Wait()
	var ev Event
	if err := json.Unmarshal(p.body, &ev); err != nil {
		t.Fatal(err)
	}
	if p.subject != "auth.events.auth0|abc" || ev.EntityID != "auth0|abc" || ev.Action != "deny" || ev.Data.Service != "catalog-api" || ev.EventID != p.msgID {
		t.Fatalf("subject %q msgID %q event %+v", p.subject, p.msgID, ev)
	}
}

func TestEmitRetriesThenSucceeds(t *testing.T) {
	p := &fakePub{failFor: 2}
	e := NewEmitter(p, fast)
	e.Emit(KindRoleRemoved, "auth0|abc", EventData{Role: "admin"})
	e.Wait()
	if p.calls != 3 || p.body == nil {
		t.Fatalf("calls = %d, delivered = %v; want delivery on the third try", p.calls, p.body != nil)
	}
}

func TestEmitDropsAfterBackoffExhausted(t *testing.T) {
	p := &fakePub{failFor: 100}
	e := NewEmitter(p, fast)
	e.Emit(KindDeny, "auth0|abc", EventData{})
	e.Wait()
	if p.calls != len(fast)+1 || p.body != nil {
		t.Fatalf("calls = %d, want %d and nothing delivered", p.calls, len(fast)+1)
	}
}

func TestEmitWithoutBusDoesNotPanic(t *testing.T) {
	NewEmitter(nil, fast).Emit(KindDeny, "auth0|abc", EventData{})
	var none *Emitter
	none.Emit(KindDeny, "auth0|abc", EventData{})
}

func TestSubjectForKeepsTokensLegal(t *testing.T) {
	if got := SubjectFor("samlp|a.b@x.com"); got != "auth.events.samlp|a_b@x_com" {
		t.Fatalf("got %q", got)
	}
}

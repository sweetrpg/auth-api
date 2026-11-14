package fga

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sweetrpg/common.go/logging"
)

// captureServer stands in for OpenFGA: it records the last write request body and answers with
// the given status and body.
func captureServer(t *testing.T, status int, reply string) (*Client, *map[string]any) {
	t.Helper()
	logging.Init()
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got = map[string]any{}
		_ = json.Unmarshal(raw, &got)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "", "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, &got
}

var tup = Tuple{User: "user:u-1", Relation: "approver", Object: "volume-edit:1"}

func TestWriteOmitsEmptySide(t *testing.T) {
	cases := map[string]struct {
		writes, deletes       []Tuple
		wantWrites, wantDelet bool
	}{
		"writes only":  {writes: []Tuple{tup}, wantWrites: true},
		"deletes only": {deletes: []Tuple{tup}, wantDelet: true},
		"both":         {writes: []Tuple{tup}, deletes: []Tuple{tup}, wantWrites: true, wantDelet: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, got := captureServer(t, http.StatusOK, `{}`)
			if err := c.Write(context.Background(), tc.writes, tc.deletes); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if _, has := (*got)["writes"]; has != tc.wantWrites {
				t.Errorf("writes present = %v, want %v (body %v)", has, tc.wantWrites, *got)
			}
			if _, has := (*got)["deletes"]; has != tc.wantDelet {
				t.Errorf("deletes present = %v, want %v (body %v)", has, tc.wantDelet, *got)
			}
		})
	}
}

func TestWriteIgnoresDuplicatesAndMissing(t *testing.T) {
	c, got := captureServer(t, http.StatusOK, `{}`)
	if err := c.Write(context.Background(), []Tuple{tup}, []Tuple{tup}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if v := (*got)["writes"].(map[string]any)["on_duplicate"]; v != "ignore" {
		t.Errorf("on_duplicate = %v, want ignore", v)
	}
	if v := (*got)["deletes"].(map[string]any)["on_missing"]; v != "ignore" {
		t.Errorf("on_missing = %v, want ignore", v)
	}
}

func TestWriteClassifiesErrors(t *testing.T) {
	cases := map[string]struct {
		status  int
		reply   string
		wantErr error
	}{
		"validation": {http.StatusBadRequest, `{"code":"validation_error","message":"relation not found"}`, ErrInvalid},
		"conflict":   {http.StatusConflict, `{"code":"write_failed_due_to_invalid_input","message":"conflict"}`, ErrConflict},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, _ := captureServer(t, tc.status, tc.reply)
			err := c.Write(context.Background(), []Tuple{tup}, nil)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Write error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestWriteServerErrorIsOpaque(t *testing.T) {
	c, _ := captureServer(t, http.StatusInternalServerError, `{"code":"internal_error","message":"db host pg-1 refused"}`)
	err := c.Write(context.Background(), []Tuple{tup}, nil)
	if err == nil || errors.Is(err, ErrInvalid) || errors.Is(err, ErrConflict) {
		t.Fatalf("Write error = %v, want an unclassified failure", err)
	}
	if got := err.Error(); got != "openfga write failed" {
		t.Errorf("error text = %q, want no server detail", got)
	}
}

func TestAPIKeyIsSentOnlyWhenSet(t *testing.T) {
	for name, tc := range map[string]struct{ key, want string }{
		"key set": {"s3cret", "Bearer s3cret"},
		"no key":  {"", ""},
	} {
		t.Run(name, func(t *testing.T) {
			var got string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Get("Authorization")
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"allowed":true}`))
			}))
			t.Cleanup(srv.Close)
			c, err := NewClient(srv.URL, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "", tc.key)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := c.Check(context.Background(), tup); err != nil {
				t.Fatalf("Check: %v", err)
			}

			if got != tc.want {
				t.Errorf("Authorization = %q, want %q", got, tc.want)
			}
		})
	}
}

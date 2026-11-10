package fga

import (
	"testing"
	"time"

	fgasdk "github.com/openfga/go-sdk"
)

func TestOldestStore(t *testing.T) {
	t0 := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	cases := map[string]struct {
		stores []fgasdk.Store
		want   string
	}{
		"earliest created wins": {[]fgasdk.Store{{Id: "b", CreatedAt: t0.Add(time.Second)}, {Id: "a", CreatedAt: t0}}, "a"},
		"tie breaks on id":      {[]fgasdk.Store{{Id: "z", CreatedAt: t0}, {Id: "m", CreatedAt: t0}}, "m"},
		"single store":          {[]fgasdk.Store{{Id: "only", CreatedAt: t0}}, "only"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := oldestStore(tc.stores).Id; got != tc.want {
				t.Errorf("oldestStore = %q, want %q", got, tc.want)
			}
		})
	}
}

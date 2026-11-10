package fga

import "testing"

func TestConfigFromEnvironment(t *testing.T) {
	cases := []struct {
		name      string
		env       map[string]string
		wantErr   bool
		wantStore string
	}{
		{name: "missing api url", env: map[string]string{}, wantErr: true},
		{name: "relative api url", env: map[string]string{EnvAPIURL: "openfga:8080"}, wantErr: true},
		{name: "unsupported scheme", env: map[string]string{EnvAPIURL: "ftp://openfga:8080"}, wantErr: true},
		{name: "default store name", env: map[string]string{EnvAPIURL: "http://openfga:8080"}, wantStore: DefaultStoreName},
		{name: "explicit store name", env: map[string]string{EnvAPIURL: "https://fga.example", EnvStoreName: "dev"}, wantStore: "dev"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := configFrom(func(k string) string { return tc.env[k] })
			if (err != nil) != tc.wantErr {
				t.Fatalf("configFrom() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && cfg.StoreName != tc.wantStore {
				t.Errorf("StoreName = %q, want %q", cfg.StoreName, tc.wantStore)
			}
		})
	}
}

package fga

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Environment variables for the OpenFGA connection. The store name identifies the store; the
// bootstrap step creates it on first start.
const (
	EnvAPIURL    = "OPENFGA_API_URL"
	EnvStoreName = "OPENFGA_STORE_NAME"
	// EnvAPIKey is the OpenFGA preshared key. It is optional: unset means no Authorization header,
	// so the same image runs before and after OpenFGA authn is enabled (PADR-0040).
	EnvAPIKey = "OPENFGA_API_KEY"
)

// DefaultStoreName is the store name used when OPENFGA_STORE_NAME is unset.
const DefaultStoreName = "sweetrpg"

// Config is the OpenFGA connection settings read from the environment.
type Config struct {
	APIURL    string
	StoreName string
	APIKey    string // empty when OpenFGA authn is not enabled
}

// ConfigFromEnvironment reads and validates the OpenFGA settings. The API URL is required; the
// store name falls back to DefaultStoreName.
func ConfigFromEnvironment() (Config, error) {
	return configFrom(os.Getenv)
}

func configFrom(get func(string) string) (Config, error) {
	raw := strings.TrimSpace(get(EnvAPIURL))
	if raw == "" {
		return Config{}, fmt.Errorf("%s is required", EnvAPIURL)
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return Config{}, errors.New(EnvAPIURL + " must be an absolute http or https URL")
	}
	name := strings.TrimSpace(get(EnvStoreName))
	if name == "" {
		name = DefaultStoreName
	}
	return Config{APIURL: raw, StoreName: name, APIKey: strings.TrimSpace(get(EnvAPIKey))}, nil
}

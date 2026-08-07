// Package auth0 verifies Auth0-issued access tokens against the tenant's
// JWKS.
package auth0

import (
	"errors"
	"fmt"

	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/common.go/util"
)

// Config is the Auth0 tenant this service verifies bearer tokens against.
type Config struct {
	Domain   string
	Audience string
}

// Issuer is the expected `iss` claim for a token from this tenant.
func (c Config) Issuer() string {
	return fmt.Sprintf("https://%s/", c.Domain)
}

// JWKSURL is this tenant's published JWKS endpoint.
func (c Config) JWKSURL() string {
	return fmt.Sprintf("https://%s/.well-known/jwks.json", c.Domain)
}

// ConfigFromEnvironment reads AUTH0_DOMAIN/AUTH0_AUDIENCE. Returns an error
// rather than crashing the process - callers (main.go) are expected to
// treat a missing config as a startup failure, not a mid-request one.
func ConfigFromEnvironment() (Config, error) {
	domain := util.GetEnv(constants.AUTH0_DOMAIN, "")
	audience := util.GetEnv(constants.AUTH0_AUDIENCE, "")
	if domain == "" || audience == "" {
		return Config{}, errors.New("AUTH0_DOMAIN and AUTH0_AUDIENCE must be set in environment")
	}
	return Config{Domain: domain, Audience: audience}, nil
}

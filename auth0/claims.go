package auth0

import "github.com/golang-jwt/jwt/v5"

// Claims are the fields verified from an Auth0-issued access token. Roles
// and per-service access aren't Auth0 claims - they're looked up separately
// by Subject once the token itself is confirmed authentic (see
// server/roles.go, server/authz.go).
type Claims struct {
	jwt.RegisteredClaims
}

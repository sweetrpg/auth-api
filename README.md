# SweetRPG Auth API

[![CI](https://github.com/sweetrpg/auth-api/actions/workflows/ci.yaml/badge.svg)](https://github.com/sweetrpg/auth-api/actions/workflows/ci.yaml)
[![License](https://img.shields.io/github/license/sweetrpg/auth-api.svg)](https://img.shields.io/github/license/sweetrpg/auth-api.svg)
[![Issues](https://img.shields.io/github/issues/sweetrpg/auth-api.svg)](https://img.shields.io/github/issues/sweetrpg/auth-api.svg)
[![PRs](https://img.shields.io/github/issues-pr/sweetrpg/auth-api.svg)](https://img.shields.io/github/issues-pr/sweetrpg/auth-api.svg)
[![Dependabot](https://badgen.net/github/dependabot/sweetrpg/auth-api)](https://badgen.net/github/dependabot/sweetrpg/auth-api)
[![Deployment](https://argocd.dev.pilgrimagesoftware.com/api/badge?name=sweetrpg-auth-api&revision=true&showAppName=true&namespace=sweetrpg-system)](https://argocd.dev.pilgrimagesoftware.com/applications/sweetrpg-auth-api)

[![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)
[![Built with love](https://ForTheBadge.com/images/badges/built-with-love.svg)](https://ForTheBadge.com/images/badges/built-with-love.svg)

Go API service for the platform's authentication/authorization domain: Auth0 token verification,
the role model, and per-service access. Split out of `users-api` - see `sweetrpg/platform`'s
`split-authz-into-auth-api` OpenSpec change for the rationale, and its `migrate-auth-users-api-to-go`
OpenSpec change for the Swift-to-Go rewrite.

Verifies Auth0-issued access tokens server-side (JWKS signature verification) and exposes
`POST /authz/check` for other services to call. See `AGENTS.md` for the role model and consumer
list.

## Running Locally

```bash
go run cmd/auth-api/main.go
```

Requires `DB_URI` (or the `DB_SCHEME`/`DB_HOST`/`DB_USER`/`DB_PW`/`DB_NAME`/`DB_OPTS` parts),
`AUTH0_DOMAIN`, and `AUTH0_AUDIENCE` in the environment. Serves on `:8000` (`BIND_ADDRESS` to
override).

## Testing

```bash
go test ./...
```

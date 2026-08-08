# AGENTS.md

This file provides guidance to Claude Code, Codex, GitHub Copilot, and other coding agents
working in this repository.

## About This Project

`auth-api` (Go) is the platform's dedicated authentication/authorization service. Split out of
`users-api` (see `sweetrpg/platform`'s `split-authz-into-auth-api` OpenSpec change) so that authz
is owned by a service with no other responsibilities, and deployed alongside `auth-web` in the
`sweetrpg-auth` namespace. Rewritten from Swift/Vapor to Go - see `sweetrpg/platform`'s
`migrate-auth-users-api-to-go` OpenSpec change for the rationale (closing an observability gap:
no tracing, no structured logging) and migration strategy (replaced the Swift deployment in place
- no parallel `api-v0`/`api-v1` deploy; the platform is pre-MVP with no versioned-API contract to
protect yet, see design.md's "Cutover strategy" decision). It reads/writes the same MongoDB
collections (`user_roles`, `service_deny_entries`, `admin_action_audit_logs`) the Swift service
produced; no data migration was needed. This repo's `auth-model` Swift package dependency was
dropped - the equivalent Go types (`Role`, `UserRole`, `ServiceDenyEntry`) live in this repo's own
`models/` package rather than a shared foundational library (see design.md's "No shared Go JWKS
foundational library" decision for the same reasoning applied to the JWKS verification code).

It verifies Auth0-issued access tokens server-side (JWKS signature verification, not a local
unverified decode) and exposes `POST /authz/check` for any other service to call with a bearer
token plus a service/action pair, getting back an allow/deny decision and the caller's roles.
Role model: `user`, `submitter`, `editor`, `moderator`, `approver`, `admin`. Access is
default-allow per service, with an explicit per-subject, per-service deny-list to restrict a
specific user.

`auth-api` holds no user profile data (no name, no email) - `UserRole`/`ServiceDenyEntry` are
keyed directly on the Auth0 `subject`, not a foreign key into any other service's `User` table.
See `sweetrpg/platform`'s `openspec/changes/split-authz-into-auth-api/design.md` for the full
rationale, including why that re-keying was necessary (the original `users-api`-hosted models
had a Fluent relation to `User` that couldn't survive the split).

### Consumers

- `auth-web`: calls `/authz/check` once at login (bearer token from Auth0's token endpoint) to
  establish a session's verified roles - the platform's sole caller of this endpoint with a real
  end-user Auth0 token.
- `admin-web`: the admin-gated role/service-access management UI. It composes `users-api`'s user
  list (id/email) with this service's `GET /api/admin/roles?subjects=...` bulk lookup, joined by
  Auth0 subject - `auth-api` has no user list of its own to serve. Mutating routes
  (`/api/admin/roles/:subject`, `/api/admin/deny-entries/:subject`) authenticate via
  `X-Internal-Service-Token` (see "Internal service auth" below), since `admin-web` never holds
  an Auth0 token of its own.

### Internal service auth (`admin-web` → `RolesController`)

`RolesController`'s `/api/admin/*` routes accept `X-Internal-Service-Token` (matching the
`INTERNAL_SERVICE_TOKEN` env var, see `InternalServiceAuth.swift`) as an alternative to an Auth0
bearer token. `admin-web` uses this exclusively - it never holds an Auth0 access token (it reads
`auth-web`'s shared session instead), so it can't present one to `/authz/check`'s or
`RolesController`'s usual bearer-token path. Whoever holds this shared secret is trusted
outright, on the assumption that `admin-web`'s own `AuthRequiredMiddleware` already verified the
acting user has the `admin` role before ever making the call - `RolesController` doesn't
re-derive who the acting admin is.

### Audit logging (fail-closed, before and after)

Every mutating `/api/admin/*` route (`addRole`, `removeRole`, `addDenyEntry`,
`removeDenyEntry`) writes an `AdminActionAuditLog` row via `RolesController.performAudited`
before running the mutation, and updates that same row to `.succeeded`/`.failed` after. If the
pre-action write itself fails, the mutation never runs - an admin action that can't be logged is
not performed, no exceptions. `actingUserSub` and `targetSubject` are both raw Auth0 `sub`
strings, not foreign keys.

Internal-service-token callers must also send `X-Acting-User-Sub` (the acting admin's Auth0
`sub`, resolved by `admin-web` from the shared session) - `verifyAdminRole` rejects the request
with 400 before touching the database if it's missing or empty, since the audit log needs to
know who to attribute the action to. Auth0 bearer-token callers don't need this header; their
own verified token's subject is used instead.

## Language and Framework

Go, following `sweetrpg/platform`'s `docs/service-conventions.md` baseline: Gin, `api-core.go`
(tracing setup, `/status/health`/`/status/ping`), `mongodb.go` (generic Mongo CRUD, connection
lifecycle), `common.go` (structured application logging), `slog-gin` (JSON HTTP access logs).
Handlers live in `server/` (one file per resource), models in `models/`, Auth0 JWKS verification
in `auth0/`, env-var/collection-name constants in `constants/`, the entrypoint in
`cmd/auth-api/main.go`. Swagger docs (`docs/`) are generated, not hand-written - see "Running
Checks Locally".

### Bootstrapping the first admin

`admin-web`'s role-management UI requires the acting user to already hold the `admin` role
(`AuthRequiredMiddleware` checks this before ever calling `RolesController`), and
`/authz/check` only returns roles that already exist in `user_roles` - there's no
self-service or automatic path to grant the very first admin. A `user_roles` document has to
be inserted directly against `auth-api`'s own database before anyone can reach `admin-web`.

Confirmed missing entirely after the `split-authz-into-auth-api` migration (2026-08-07): the
`user_roles` collection in `sweetrpg-auth` was empty post-split, so every login returned zero
roles for every subject, admins included. There is no seed script or migration that
carries roles forward from wherever `users-api` held them before the split - if this happens
again after a similar migration, that's the first thing to check.

To bootstrap: insert a document into the `user_roles` collection (`sweetrpg-auth` database)
with `_id` (a UUID - `models.UserRole` has no driver-level default, so a driver-level insert
must set one explicitly), `subject` (the Auth0 `sub`, e.g. `github|<id>` - visible in
`auth-api`'s `/authz/check` request logs during a login attempt), `role: "admin"`, and
`createdAt` (a datetime; nothing backfills it for a driver-level insert). Use the `auth-api`
Atlas database user's own credentials (`auth-api-db-credentials` Secret in `sweetrpg-auth`,
scoped `readWrite` to `sweetrpg-auth` only) rather than the shared admin user. Once the document
exists, the user must log out and back in through `auth-web` - the session's roles are only
resolved once, at login.

**`_id` must be inserted as a BSON UUID (Binary subtype 0x00), not a plain string.**
`models.UserRole`'s `ID` field is `uuid.UUID` (`github.com/google/uuid`), and the Go driver's
default codec marshals that type as `{"$binary": {"base64": "...", "subType": "00"}}` - the raw
16 bytes, base64-encoded - not the human-readable `xxxxxxxx-xxxx-...` string form. A document
inserted with `_id` as a string decodes with `error decoding key _id: cannot decode string into
an array`, which surfaces to every login attempt as `auth-web`'s generic "Login is temporarily
unavailable" error. Hit this exactly once, 2026-08-08 (the day after the migration above), on the
very bootstrap document the migration note above says to create - built the correct BSON value
with:

```go
id, _ := uuid.Parse("<uuid-string>")
b, _ := bson.MarshalExtJSON(struct{ ID uuid.UUID `bson:"_id"` }{ID: id}, false, false)
// b contains the {"$binary": {...}} form to use as `_id` in the inserted document
```

Same applies to `models.ServiceDenyEntry` and `models.AuditLog` - both also key `_id` on
`uuid.UUID`.

## Deployment

`kubernetes/` (base + `overlays/{dev,local}`) deploys this service into the `sweetrpg-auth`
namespace, server-to-server only - no Ingress, since every caller (`auth-web`, `admin-web`)
reaches it over in-cluster DNS (`api-v1.sweetrpg-auth.svc.cluster.local:8000` - the Service
follows the platform's versioned-Service naming convention, not a plain `auth-api` name despite
what this doc used to say; confirmed the hard way when `auth-web`'s hardcoded default host
pointed at a Service that doesn't exist and broke login in dev). `DB_URI` (or the
`DB_SCHEME`/`DB_HOST`/`DB_USER`/`DB_PW`/`DB_NAME`/`DB_OPTS` parts, its own `sweetrpg-auth`
database via a dedicated `AtlasDatabaseUser`), `AUTH0_DOMAIN`/`AUTH0_AUDIENCE` (the one shared
Auth0 application - see `auth-web`'s `AGENTS.md`), and `INTERNAL_SERVICE_TOKEN` all come from
Akeyless via `ExternalSecret`s, not the configmap. This service holds no session store of its own
- it's a stateless, bearer-token-only API.

## Committing Code

[Conventional Commits](https://www.conventionalcommits.org/): `<type>(<scope>): <description>`.

## Branches and Workflow

Git-flow (see `docs/git-flow.md` in `sweetrpg/platform`): `develop` is the integration branch,
`master` reflects the latest release. Feature/fix branches off `develop`, PR back into `develop`.

## Running Checks Locally

```bash
go build ./...
go vet ./...
go test ./...
```

`go run cmd/auth-api/main.go` serves on `:8000` (`BIND_ADDRESS` to override). Regenerate Swagger
docs after changing handler annotations:

```bash
go run github.com/swaggo/swag/cmd/swag@latest init -d cmd/auth-api/,server/,models/ --parseDependency --parseInternal
```

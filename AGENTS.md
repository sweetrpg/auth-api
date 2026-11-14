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
  Auth0 subject - `auth-api` has no user list of its own to serve. Every `/api/admin/*` call carries
  the signed-in admin's own bearer token, forwarded by `admin-web` (PADR-0037: there is no service
  token; the former `X-Internal-Service-Token` branch and its secret were removed).

### Audit logging (fail-closed, before and after)

Every mutating `/api/admin/*` route (`addRole`, `removeRole`, `addDenyEntry`,
`removeDenyEntry`) writes an `AdminActionAuditLog` row via `RolesController.performAudited`
before running the mutation, and updates that same row to `.succeeded`/`.failed` after. If the
pre-action write itself fails, the mutation never runs - an admin action that can't be logged is
not performed, no exceptions. `actingUserSub` and `targetSubject` are both raw Auth0 `sub`
strings, not foreign keys.

The acting administrator is the verified bearer token's subject, and a bearer-token caller's
canonical user is resolved with that token; if it cannot be, the subject is recorded and the cause
logged at ERROR.

### Roles and deny entries belong to the person

`user_roles` and `service_deny_entries` rows carry the Auth0 `subject` they were granted under
and, once known, the canonical `user_id`. Every lookup (`/authz/check`, `verifyAdminRole`, the
admin reads and writes) matches a row by `user_id` of the caller's user OR its `subject`, so a
role or deny entry applies to all of a person's linked logins and removing it through any login
removes it for the person. `identity.Resolver` finds the user with a real user's bearer token only
(PADR-0037, no service token): `/authz/check` uses the caller's own token against users-api
`GET /profile` (cached ~1 min; for the `users-api` service it uses the cache only, since users-api
answers `/profile` by calling `/authz/check`); admin reads and writes use the administrator's
forwarded bearer with `POST /internal/resolve-subjects`. When users-api is unreachable, the lookup falls back to the subject alone and logs a WARN.
New rows store both ids. Existing rows get `user_id` from the one-off
`ADMIN_BEARER_TOKEN=... go run ./cmd/backfill-user-ids`, run as an admin user.
The admin API still takes a subject in the path: pass any of the user's subjects.

### Service registry

`registry/services.json` lists the services a user can be denied (`id` is what the service passes
to `/authz/check`, `name` is for display). `GET /api/admin/services` returns it as `[{id, name}]`
and `POST /api/admin/deny-entries/:subject` rejects other names with 400 `unknown_service`.
`/authz/check` stays default-allow for any name, so a new service works before it is listed;
add it to the file to make it deniable.

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
Atlas database user's own credentials (`api-db` Secret in `sweetrpg-auth`, scoped `readWrite`
to `sweetrpg-auth` only) rather than the shared admin user. Once the document exists, the user
must log out and back in through `auth-web` - the session's roles are only resolved once, at
login.

## Deployment

`kubernetes/` (base + `overlays/{dev,local}`) deploys this service into the `sweetrpg-auth`
namespace, server-to-server only - no Ingress, since every caller (`auth-web`, `admin-web`)
reaches it over in-cluster DNS (`api-v1.sweetrpg-auth.svc.cluster.local:8000` - the Service
follows the platform's versioned-Service naming convention, not a plain `auth-api` name despite
what this doc used to say; confirmed the hard way when `auth-web`'s hardcoded default host
pointed at a Service that doesn't exist and broke login in dev). `DB_URI` (or the
`DB_SCHEME`/`DB_HOST`/`DB_USER`/`DB_PW`/`DB_NAME`/`DB_OPTS` parts, its own `sweetrpg-auth`
database via a dedicated `AtlasDatabaseUser`), `AUTH0_DOMAIN`/`AUTH0_AUDIENCE` (the one shared
Auth0 application - see `auth-web`'s `AGENTS.md`) come from
Akeyless via `ExternalSecret`s, not the configmap. This service holds no session store of its own
- it's a stateless, bearer-token-only API.

## Rate limiting

Per-client/IP rate limiting is on by default via the shared `api-core.go/ratelimit` middleware
(Redis-backed counters keyed by `X-API-Key` else client IP, `cheap` tier for `/status/*`,
`standard` otherwise, 429 on exceed). The former in-process per-IP `rate.Limiter` map and the
`RATE_LIMIT_PER_SECOND` env var were removed. This makes auth-api Redis-dependent at request
time: a rate-limit-store outage returns 503 (fail closed, never unlimited). `REDIS_HOST`/
`REDIS_PORT` are in the dev configmap; `REDIS_PASS` comes from the `api-cache` `ExternalSecret`.
Tier defaults are looser than other services (`RATE_LIMIT_STANDARD` 300/60) so the synchronous
catalog-api -> `/authz/check` chain is not throttled. See `platform`'s
`openspec/changes/fix-rate-limiting-per-client-ip`.

## OpenFGA relationship authorization

Relationship-scoped checks run against an OpenFGA store (`fga/`, `server/fga.go`). The role model
and `/authz/check` are unchanged; OpenFGA is an additional decision path (`evaluate-openfga-
authorization`, PADR-0035, PADR-0038).

- **Model:** `fga/model.fga` is the source of truth. Bootstrap converts it to JSON, compares it
  with the store's latest model, and writes a new version only when it differs.
- **Startup:** `OPENFGA_API_URL` (required) and `OPENFGA_STORE_NAME` (default `sweetrpg`). Bootstrap
  finds or creates the store and exits the process on failure, so the pod restarts.
- **Datastore:** OpenFGA runs against an external PostgreSQL database, not Atlas. The
  `openfga-datastore` ExternalSecret composes `OPENFGA_DATASTORE_URI` from the Akeyless item
  `/sweetrpg/auth/openfga/datastore`. The `openfga` Deployment runs `migrate` as an init container.
- **Tuple subjects are canonical user IDs:** tuples use `user:<canonical user id>`, never an Auth0
  subject, so a relation follows the person across linked logins (see "Roles and deny entries
  belong to the person"). The tuple endpoints reject any user that is not `user:<id>` without
  `|`, `:`, `#` or `*`.
- **`POST /authz/check-relation`** takes `{object, relation}` (`object` is `type:id`) and a bearer
  token. It resolves the caller's canonical user with `principalFor` and checks `user:<id>`
  against the store, returning `{allowed}`. An invalid token never reaches the store. When the
  canonical user cannot be resolved (users-api unreachable, or the login has no user) or the
  store errors, it returns 503 and is never treated as allowed.
- **`/internal/openfga/tuples`** (`POST` writes and deletes in one batch, `GET` pages through an
  object's tuples) requires a bearer token whose subject holds `openfga-writer`. Admin does not imply
  it. Writes run through `performAudited`, and the audit detail lists every tuple in the batch. A
  failed batch applies nothing.
- **Write errors:** OpenFGA validation failures (unknown relation, a tuple that violates the model)
  return 400 `invalid_tuples`, an OpenFGA 409 returns 409 `tuple_conflict`, and transport or server
  failures return 503. The audit row stores a short fixed message, never OpenFGA's response text.
- **Idempotent writes:** batches send `on_duplicate=ignore` and `on_missing=ignore`, so writing a
  tuple that exists and deleting one that does not are no-ops. A reconciler can resend a batch
  after a timeout without failing it. The cost is that a typo in a delete is not reported.
- **Store bootstrap:** auth-api runs 2 or more replicas (HPA `minReplicas: 2`), so replicas can
  create the store at the same moment. After creating it, a replica re-lists and uses the oldest
  store of that name, deleting its own if it lost.
- **Consumer contract:** call `check-relation` for each decision. Cache results briefly and never
  past an access revocation window. Reconcile derived tuples from the consumer's own data through
  the tuple endpoints. See PADR-0038 for how a reconciler obtains its token.

## Session tuple endpoints (PADR-0040)

Users write the OpenFGA tuples for sessions they hold a relation on, so `initiative-api` can keep
membership tuples current on the request path. Every call authenticates the caller's own bearer,
resolves the canonical user, and refuses a user with a deny entry for `initiative-api`. Tuples are
necessary but not sufficient: `initiative-api` also requires a live Mongo membership record.

- `POST /authz/sessions` mints a 24-hex session ID, writes `user:<caller> gm session:<id>`, and
  records it in `session_mints`. IDs always come from here. At most `MAX_OPEN_MINTS` (100) open
  mints per user, 20 per user per hour (`MINTS_PER_USER_HOUR`), 600 per hour overall
  (`MINTS_GLOBAL_HOUR`).
- `DELETE /authz/sessions/{id}` (caller holds `gm`) deletes every tuple on the session and closes
  its mint.
- `POST /authz/session-tuples` `{session_id, writes, deletes}`, at most 20 tuples, relations
  `co_gm`/`player`/`observer` only, object always `session:<id>`. Caller needs `can_view` to delete
  only their own tuple, `gm` for any `co_gm` tuple, `can_edit` otherwise. At most
  `MAX_SESSION_TUPLES` (200) tuples per session.
- `GET /internal/openfga/session-mints?min_age=15m[&after=<next>][&limit=n]` (returns `{mints, next}`,
  ordered by created_at then id; `next` is empty on the last page) and
  `POST /internal/openfga/session-mints/{id}/close` require `openfga-writer` (the reconciler's
  garbage collection). Closed mints are removed by a TTL
  index 30 days after `closed_at`.
- Every write is audited before it runs. Rate limits use Redis; with Redis down the endpoints answer
  503 rather than run unlimited.
- `OPENFGA_API_KEY` is optional: when set it is sent as the OpenFGA preshared key on Bootstrap and
  every call; unset sends nothing. Enabling OpenFGA authn is a separate rollout step.

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

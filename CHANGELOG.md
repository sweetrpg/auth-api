## [0.13.0] - 2026-11-14

### 🚀 Features

- *(fga)* Add session and encounter types to the OpenFGA model
- *(fga)* Read an optional OpenFGA preshared key
- *(authz)* Add user-scoped session tuple endpoints

### 🐛 Bug Fixes

- *(authz)* Page mint listing, count real tuple changes, idempotent end
- *(authz)* Index mints by created_at then id; reword the end-retry test

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.12.0
## [0.12.0] - 2026-11-12

### 🚀 Features

- *(events)* Publish deny and role_removed to AUTH_EVENTS after commit
- *(registry)* Add initiative-api so administrators can deny it
- *(kubernetes)* Wire AUTH_EVENTS publisher NATS user in dev

### 🐛 Bug Fixes

- *(authz)* Key OpenFGA on canonical user and harden tuple writes

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.11.0
## [0.11.0] - 2026-11-10

### 🚀 Features

- *(authz)* Add OpenFGA check-relation and internal tuple endpoints

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.10.0
- Update Go to 1.26.10
## [0.10.0] - 2026-11-05

### 🚀 Features

- *(admin)* Remove the inbound internal service token branch

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.9.0
## [0.9.0] - 2026-11-05

### 🚀 Features

- *(roles)* Roles and deny entries belong to the person

### 🐛 Bug Fixes

- *(roles)* Look up users with bearer tokens, not a service token

### 🧪 Testing

- *(models)* Decode the unresolved row into a fresh value

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.8.0
## [0.8.0] - 2026-11-04

### 🚀 Features

- *(admin)* List valid service names and reject unknown deny targets

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.7.3
## [0.7.3] - 2026-11-04

### 🐛 Bug Fixes

- *(roles)* Record the acting subject when its canonical id cannot be resolved

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.7.2
## [0.7.2] - 2026-11-04

### 🐛 Bug Fixes

- *(roles)* Read-only admin calls need no acting user

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.7.1
- *(debug)* Restrict workflow token permissions
## [0.7.1] - 2026-10-29

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.7.0
## [0.7.0] - 2026-09-09

### 🚀 Features

- *(ratelimit)* Replace in-process per-IP limiter with shared api-core middleware (#106)

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.6.0
- *(deploy)* Add per-client rate-limit and redis env to dev overlay (#106)
## [0.6.0] - 2026-09-08

### 🚀 Features

- *(auth-api)* Resolve canonical user IDs for admin writes
- *(admin)* Add GET /api/admin/deny-entries/stats restricted-user count

### 🐛 Bug Fixes

- Increase refresh interval

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.5.1
## [0.5.1] - 2026-09-04

### 🐛 Bug Fixes

- *(ratelimit)* Scope per caller, exempt health checks, raise default rate

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.5.0
## [0.5.0] - 2026-09-03

### 🚀 Features

- Adopt audit-fields convention on user_roles and service_deny_entries

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.4.2
- Update to standard labels
## [0.4.2] - 2026-08-25

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.4.1
- Tighten GOGC to 90 on auth-api deployment
## [0.4.1] - 2026-08-25

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.4.0
- Set GOMEMLIMIT and GOGC on auth-api deployment
## [0.4.0] - 2026-08-21

### 🚀 Features

- *(local)* Add MongoDB database configuration to local overlay
- *(kubernetes)* Add Prometheus metrics and service resources

### 🐛 Bug Fixes

- *(kubernetes)* Fix cpu resource limit quantity that never matched ArgoCD's applied manifest

### 📚 Documentation

- Describe the Go service instead of Vapor in README/AGENTS.md

### ⚙️ Miscellaneous Tasks

- Remove Swift/Vapor source tree, no longer used
- *(release)* Merge master into develop after v0.3.0
- Add reloader annotation, pod monitor
- Add license file
## [0.3.0] - 2026-08-11

### 🚀 Features

- Gate continuous profiling behind the profiling-enabled feature flag

### 🐛 Bug Fixes

- *(ci)* Scope Docker Build's concurrency group by ref

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.2.1
## [0.2.1] - 2026-08-07

### 📚 Documentation

- Document first-admin bootstrapping and correct Service hostname

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.2.0
## [0.2.0] - 2026-08-07

### 🚀 Features

- Scaffold Go rewrite of auth-api

### 🐛 Bug Fixes

- Log the real reason for a /authz/check verification failure
- Check resp.Body.Close() error to satisfy golangci-lint errcheck

### ⚙️ Miscellaneous Tasks

- Switch auth-api to the Go build (CI, Dockerfile, Kubernetes)
- *(release)* Merge master into develop after v0.1.2
## [0.1.2] - 2026-08-07

### 🐛 Bug Fixes

- Build DATABASE_URL from DB_* env parts instead of requiring it whole

### ⚙️ Miscellaneous Tasks

- *(release)* Merge master into develop after v0.1.1
## [0.1.1] - 2026-08-07

### ⚙️ Miscellaneous Tasks

- Remove image patch
- *(release)* Merge master into develop after v0.1.0
## [0.1.0] - 2026-08-07

### 🚀 Features

- Scaffold auth-api service
- Add kubernetes manifests

### 🐛 Bug Fixes

- Db secret
- *(kubernetes)* Authenticate AtlasDatabaseUser against admin, not app db

### ⚙️ Miscellaneous Tasks

- Clean up the files
- Add initial empty CHANGELOG.md


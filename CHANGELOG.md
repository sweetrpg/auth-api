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


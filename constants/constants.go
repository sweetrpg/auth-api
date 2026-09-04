package constants

// Environment variable names
const (
	HEALTH_TOKEN             = "HEALTH_TOKEN"
	ALLOWED_ORIGINS          = "ALLOWED_ORIGINS"
	PYROSCOPE_SERVER_ADDRESS = "PYROSCOPE_SERVER_ADDRESS"
	PYROSCOPE_TENANT_ID      = "PYROSCOPE_TENANT_ID"

	// INTERNAL_SERVICE_TOKEN gates the /api/admin/* routes; see
	// server.hasValidInternalServiceToken.
	INTERNAL_SERVICE_TOKEN = "INTERNAL_SERVICE_TOKEN"

	// AUTH0_DOMAIN and AUTH0_AUDIENCE configure the Auth0 tenant this service
	// verifies bearer tokens against; see auth0.ConfigFromEnvironment.
	AUTH0_DOMAIN   = "AUTH0_DOMAIN"
	AUTH0_AUDIENCE = "AUTH0_AUDIENCE"

	// RATE_LIMIT_PER_SECOND is the sustained per-caller request rate for
	// main.RateLimiter; api-core.go's RATE_LIMIT env var supplies the burst.
	RATE_LIMIT_PER_SECOND = "RATE_LIMIT_PER_SECOND"
)

// Value constants
const (
	ServiceName = "auth-api"

	// ProfilingEnabledFlag is the feature-flag key gating continuous
	// profiling, evaluated via api-core.go/featureflags. Replaces the old
	// PYROSCOPE_SERVER_ADDRESS-presence check; see
	// openspec/changes/pyroscope-profiling-feature-flag in sweetrpg/platform.
	ProfilingEnabledFlag = "profiling-enabled"

	// UserRolesCollection is the MongoDB collection name for role assignments,
	// unchanged from the Swift service's Fluent schema (AuthModel's
	// UserRole.v20260805.schemaName).
	UserRolesCollection = "user_roles"

	// ServiceDenyEntriesCollection is the MongoDB collection name for
	// per-service deny entries, unchanged from the Swift service's Fluent
	// schema (AuthModel's ServiceDenyEntry.v20260805.schemaName).
	ServiceDenyEntriesCollection = "service_deny_entries"

	// AdminActionAuditLogCollection is the MongoDB collection name for
	// write-route audit records.
	AdminActionAuditLogCollection = "admin_action_audit_logs"
)

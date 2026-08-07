package models

// Role is the platform's fixed role model. A user may hold more than one
// role at once (e.g. user and editor) - deliberately not a generic
// permissions matrix, see design.md's "Role model" decision. Matches
// AuthModel's Swift Role enum exactly.
type Role string

const (
	RoleUser      Role = "user"
	RoleSubmitter Role = "submitter"
	RoleEditor    Role = "editor"
	RoleModerator Role = "moderator"
	RoleApprover  Role = "approver"
	RoleAdmin     Role = "admin"
)

var validRoles = map[Role]struct{}{
	RoleUser:      {},
	RoleSubmitter: {},
	RoleEditor:    {},
	RoleModerator: {},
	RoleApprover:  {},
	RoleAdmin:     {},
}

// ParseRole validates s against the platform's fixed role model.
func ParseRole(s string) (Role, bool) {
	r := Role(s)
	_, ok := validRoles[r]
	return r, ok
}

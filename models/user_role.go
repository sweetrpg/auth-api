package models

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/mongodb.go/database"
)

// UserRole is a single role assignment. A subject with no rows here defaults
// to RoleUser (see design.md's "Role model" decision) - this collection only
// holds assignments beyond that default. Keyed on the Auth0 subject directly
// rather than a foreign key into users-api's User collection - auth-api holds
// no profile data of its own to relate to.
type UserRole struct {
	ID      uuid.UUID `bson:"_id" json:"id"`
	Subject string    `bson:"subject" json:"subject"`
	// UserID is the canonical user the role belongs to; empty on rows written before roles
	// followed the person (matched through Subject until the backfill sets it).
	UserID string `bson:"user_id,omitempty" json:"user_id,omitempty"`
	Role   Role   `bson:"role" json:"role"`
	// Platform audit fields (PADR-0001). user_roles are hard-delete security-control records
	// (PADR-0027), so there is no deleted_* pair. A row is only ever added or removed, never
	// updated in place, so updated_* always equals created_*.
	CreatedBy string    `bson:"created_by" json:"created_by"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
	UpdatedBy string    `bson:"updated_by" json:"updated_by"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
}

// ListRolesFor returns every role row that applies to the principal.
func ListRolesFor(ctx context.Context, p Principal) ([]*UserRole, error) {
	return database.Query[UserRole](constants.UserRolesCollection, p.filter(), nil, nil, 0, 0)
}

// HasRole reports whether the principal already holds role.
func HasRole(ctx context.Context, p Principal, role Role) (bool, error) {
	rows, err := database.Query[UserRole](constants.UserRolesCollection, p.with("role", role), nil, nil, 0, 1)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// AddRole inserts a role assignment for the principal attributed to actingUserID. Callers should
// check HasRole first to keep the operation idempotent.
func AddRole(ctx context.Context, p Principal, role Role, actingUserID string) error {
	now := time.Now().UTC()
	doc := UserRole{
		ID: uuid.New(), Subject: p.Subject, UserID: p.UserID, Role: role,
		CreatedBy: actingUserID, CreatedAt: now, UpdatedBy: actingUserID, UpdatedAt: now,
	}
	_, err := database.Db.Collection(constants.UserRolesCollection).InsertOne(ctx, doc)
	return err
}

// RemoveRole deletes the principal's role rows, whichever login or user they were keyed by.
func RemoveRole(ctx context.Context, p Principal, role Role) error {
	_, err := database.Db.Collection(constants.UserRolesCollection).DeleteMany(ctx, p.with("role", role))
	return err
}

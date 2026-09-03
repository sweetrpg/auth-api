package models

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/mongodb.go/database"
	"go.mongodb.org/mongo-driver/bson"
)

// UserRole is a single role assignment. A subject with no rows here defaults
// to RoleUser (see design.md's "Role model" decision) - this collection only
// holds assignments beyond that default. Keyed on the Auth0 subject directly
// rather than a foreign key into users-api's User collection - auth-api holds
// no profile data of its own to relate to.
type UserRole struct {
	ID      uuid.UUID `bson:"_id" json:"id"`
	Subject string    `bson:"subject" json:"subject"`
	Role    Role      `bson:"role" json:"role"`
	// Platform audit fields (PADR-0001). user_roles are hard-delete security-control records
	// (PADR-0027), so there is no deleted_* pair. A row is only ever added or removed, never
	// updated in place, so updated_* always equals created_*.
	CreatedBy string    `bson:"created_by" json:"created_by"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
	UpdatedBy string    `bson:"updated_by" json:"updated_by"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
}

// ListRolesForSubject returns every role row for subject.
func ListRolesForSubject(ctx context.Context, subject string) ([]*UserRole, error) {
	return database.Query[UserRole](
		constants.UserRolesCollection,
		bson.D{{Key: "subject", Value: subject}},
		nil, nil, 0, 0,
	)
}

// HasRole reports whether subject already holds role.
func HasRole(ctx context.Context, subject string, role Role) (bool, error) {
	rows, err := database.Query[UserRole](
		constants.UserRolesCollection,
		bson.D{{Key: "subject", Value: subject}, {Key: "role", Value: role}},
		nil, nil, 0, 1,
	)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// AddRole inserts a new role assignment attributed to actingUserID. Callers should check
// HasRole first to keep the operation idempotent, matching the Swift service's behavior
// (a no-op, not a duplicate, when the subject already holds the role).
func AddRole(ctx context.Context, subject string, role Role, actingUserID string) error {
	now := time.Now().UTC()
	doc := UserRole{
		ID: uuid.New(), Subject: subject, Role: role,
		CreatedBy: actingUserID, CreatedAt: now, UpdatedBy: actingUserID, UpdatedAt: now,
	}
	_, err := database.Db.Collection(constants.UserRolesCollection).InsertOne(ctx, doc)
	return err
}

// RemoveRole deletes every role row matching subject+role (there should be at
// most one).
func RemoveRole(ctx context.Context, subject string, role Role) error {
	_, err := database.Db.Collection(constants.UserRolesCollection).DeleteMany(ctx, bson.D{
		{Key: "subject", Value: subject}, {Key: "role", Value: role},
	})
	return err
}

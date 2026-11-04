package models

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/mongodb.go/database"
	"go.mongodb.org/mongo-driver/bson"
)

// ServiceDenyEntry is an explicit deny of one subject's access to one
// service. Absence of a row means access is allowed - see design.md's
// "Per-service access: default-allow + deny-list" decision. Keyed on the
// Auth0 subject directly, same rationale as UserRole.
type ServiceDenyEntry struct {
	ID      uuid.UUID `bson:"_id" json:"id"`
	Subject string    `bson:"subject" json:"subject"`
	// UserID: see UserRole.UserID.
	UserID  string `bson:"user_id,omitempty" json:"user_id,omitempty"`
	Service string `bson:"service" json:"service"`
	// Platform audit fields (PADR-0001). service_deny_entries are hard-delete security-control
	// records (PADR-0027), so there is no deleted_* pair. A row is only ever added or removed,
	// never updated in place, so updated_* always equals created_*.
	CreatedBy string    `bson:"created_by" json:"created_by"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
	UpdatedBy string    `bson:"updated_by" json:"updated_by"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
}

// CountRestrictedSubjects returns the number of distinct people with at least one deny entry.
// service_deny_entries are hard-delete records (PADR-0027), so every row is an active
// restriction. A person is counted once however many services or linked logins are denied; a
// row without a user_id counts by its subject.
func CountRestrictedSubjects(ctx context.Context) (int, error) {
	coll := database.Db.Collection(constants.ServiceDenyEntriesCollection)
	users, err := coll.Distinct(ctx, "user_id", bson.D{{Key: "user_id", Value: bson.D{{Key: "$exists", Value: true}}}})
	if err != nil {
		return 0, err
	}
	legacy, err := coll.Distinct(ctx, "subject", bson.D{{Key: "user_id", Value: bson.D{{Key: "$exists", Value: false}}}})
	if err != nil {
		return 0, err
	}
	return len(users) + len(legacy), nil
}

// ListDenyEntriesFor returns every deny entry that applies to the principal.
func ListDenyEntriesFor(ctx context.Context, p Principal) ([]*ServiceDenyEntry, error) {
	return database.Query[ServiceDenyEntry](constants.ServiceDenyEntriesCollection, p.filter(), nil, nil, 0, 0)
}

// HasDenyEntry reports whether the principal is denied access to service.
func HasDenyEntry(ctx context.Context, p Principal, service string) (bool, error) {
	rows, err := database.Query[ServiceDenyEntry](constants.ServiceDenyEntriesCollection, p.with("service", service), nil, nil, 0, 1)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// AddDenyEntry inserts a deny entry for the principal attributed to actingUserID. Callers should
// check HasDenyEntry first to keep the operation idempotent.
func AddDenyEntry(ctx context.Context, p Principal, service, actingUserID string) error {
	now := time.Now().UTC()
	doc := ServiceDenyEntry{
		ID: uuid.New(), Subject: p.Subject, UserID: p.UserID, Service: service,
		CreatedBy: actingUserID, CreatedAt: now, UpdatedBy: actingUserID, UpdatedAt: now,
	}
	_, err := database.Db.Collection(constants.ServiceDenyEntriesCollection).InsertOne(ctx, doc)
	return err
}

// RemoveDenyEntry deletes the principal's deny entries for service.
func RemoveDenyEntry(ctx context.Context, p Principal, service string) error {
	_, err := database.Db.Collection(constants.ServiceDenyEntriesCollection).DeleteMany(ctx, p.with("service", service))
	return err
}

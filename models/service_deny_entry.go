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
	Service string    `bson:"service" json:"service"`
	// Platform audit fields (PADR-0001). service_deny_entries are hard-delete security-control
	// records (PADR-0027), so there is no deleted_* pair. A row is only ever added or removed,
	// never updated in place, so updated_* always equals created_*.
	CreatedBy string    `bson:"created_by" json:"created_by"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
	UpdatedBy string    `bson:"updated_by" json:"updated_by"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
}

// ListDenyEntriesForSubject returns every deny entry for subject.
func ListDenyEntriesForSubject(ctx context.Context, subject string) ([]*ServiceDenyEntry, error) {
	return database.Query[ServiceDenyEntry](
		constants.ServiceDenyEntriesCollection,
		bson.D{{Key: "subject", Value: subject}},
		nil, nil, 0, 0,
	)
}

// HasDenyEntry reports whether subject is already denied access to service.
func HasDenyEntry(ctx context.Context, subject, service string) (bool, error) {
	rows, err := database.Query[ServiceDenyEntry](
		constants.ServiceDenyEntriesCollection,
		bson.D{{Key: "subject", Value: subject}, {Key: "service", Value: service}},
		nil, nil, 0, 1,
	)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// AddDenyEntry inserts a new deny entry attributed to actingUserID. Callers should check
// HasDenyEntry first to keep the operation idempotent.
func AddDenyEntry(ctx context.Context, subject, service, actingUserID string) error {
	now := time.Now().UTC()
	doc := ServiceDenyEntry{
		ID: uuid.New(), Subject: subject, Service: service,
		CreatedBy: actingUserID, CreatedAt: now, UpdatedBy: actingUserID, UpdatedAt: now,
	}
	_, err := database.Db.Collection(constants.ServiceDenyEntriesCollection).InsertOne(ctx, doc)
	return err
}

// RemoveDenyEntry deletes every deny entry matching subject+service (there
// should be at most one).
func RemoveDenyEntry(ctx context.Context, subject, service string) error {
	_, err := database.Db.Collection(constants.ServiceDenyEntriesCollection).DeleteMany(ctx, bson.D{
		{Key: "subject", Value: subject}, {Key: "service", Value: service},
	})
	return err
}

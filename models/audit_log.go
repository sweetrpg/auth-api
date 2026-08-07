// Package models defines the persisted document shapes for auth-api.
package models

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/mongodb.go/database"
	"go.mongodb.org/mongo-driver/bson"
)

// AuditStatus tracks whether the mutation an AdminActionAuditLog record
// covers actually completed.
type AuditStatus string

const (
	AuditAttempted AuditStatus = "attempted"
	AuditSucceeded AuditStatus = "succeeded"
	AuditFailed    AuditStatus = "failed"
)

// AdminActionAuditLog attributes a write-route mutation (grant/revoke a
// role, add/remove a service deny entry) to the acting user who made it.
// Written *before* the mutation is attempted (status "attempted") and
// updated *after* it completes - see RecordAuditAttempt and CompleteAudit.
// If the "before" write fails, the mutation must not be performed: an audit
// trail that can silently fail to exist is not an audit trail. Both
// ActingUserSub and TargetSubject are raw Auth0 sub strings, not foreign
// keys - auth-api holds no profile data to key against.
type AdminActionAuditLog struct {
	ID            uuid.UUID   `bson:"_id" json:"id"`
	ActingUserSub string      `bson:"actingUserSub" json:"actingUserSub"`
	Action        string      `bson:"action" json:"action"`
	TargetSubject string      `bson:"targetSubject" json:"targetSubject"`
	Detail        string      `bson:"detail" json:"detail"`
	Status        AuditStatus `bson:"status" json:"status"`
	AttemptedAt   time.Time   `bson:"attemptedAt" json:"attemptedAt"`
	CompletedAt   *time.Time  `bson:"completedAt,omitempty" json:"completedAt,omitempty"`
	ErrorMessage  string      `bson:"errorMessage,omitempty" json:"errorMessage,omitempty"`
}

// RecordAuditAttempt writes the "attempted" audit record for a write-route
// mutation before the mutation itself runs. Returns the record's ID for a
// later CompleteAudit call. Callers must not perform the mutation if this
// returns an error.
func RecordAuditAttempt(ctx context.Context, actingUserSub, action, targetSubject, detail string) (uuid.UUID, error) {
	entry := AdminActionAuditLog{
		ID:            uuid.New(),
		ActingUserSub: actingUserSub,
		Action:        action,
		TargetSubject: targetSubject,
		Detail:        detail,
		Status:        AuditAttempted,
		AttemptedAt:   time.Now().UTC(),
	}
	_, err := database.Db.Collection(constants.AdminActionAuditLogCollection).InsertOne(ctx, entry)
	return entry.ID, err
}

// CompleteAudit updates an audit record to its final status after the
// mutation it covers has run. Best-effort: a failure here doesn't undo a
// mutation that already happened, so callers should log a warning rather
// than fail the request on error.
func CompleteAudit(ctx context.Context, id uuid.UUID, status AuditStatus, errMessage string) error {
	update := bson.M{"status": status, "completedAt": time.Now().UTC()}
	if errMessage != "" {
		update["errorMessage"] = errMessage
	}
	_, err := database.Db.Collection(constants.AdminActionAuditLogCollection).UpdateByID(ctx, id, bson.M{"$set": update})
	return err
}

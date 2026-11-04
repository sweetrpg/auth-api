package models

import (
	"context"
	"fmt"

	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/mongodb.go/database"
	"go.mongodb.org/mongo-driver/bson"
)

// SubjectResolver maps Auth0 subjects to canonical user IDs; unknown subjects are omitted.
type SubjectResolver func(ctx context.Context, subjects []string) (map[string]string, error)

// BackfillUserIDs sets user_id on role and deny-entry rows written when they were keyed by login
// only, so they follow the person. Idempotent: rows that have a user_id, and subjects users-api
// does not know, are left alone. It returns how many rows it updated.
func BackfillUserIDs(ctx context.Context, resolve SubjectResolver) (int64, error) {
	var total int64
	for _, coll := range []string{constants.UserRolesCollection, constants.ServiceDenyEntriesCollection} {
		n, err := backfillCollection(ctx, coll, resolve)
		total += n
		if err != nil {
			return total, fmt.Errorf("backfilling %s: %w", coll, err)
		}
	}
	return total, nil
}

func backfillCollection(ctx context.Context, name string, resolve SubjectResolver) (int64, error) {
	coll := database.Db.Collection(name)
	missing := bson.D{{Key: "user_id", Value: bson.D{{Key: "$exists", Value: false}}}}
	values, err := coll.Distinct(ctx, "subject", missing)
	if err != nil {
		return 0, err
	}
	subjects := make([]string, 0, len(values))
	for _, v := range values {
		if s, ok := v.(string); ok && s != "" {
			subjects = append(subjects, s)
		}
	}
	if len(subjects) == 0 {
		return 0, nil
	}
	resolved, err := resolve(ctx, subjects)
	if err != nil {
		return 0, err
	}
	var updated int64
	for subject, userID := range resolved {
		if userID == "" {
			continue
		}
		res, err := coll.UpdateMany(ctx,
			bson.D{{Key: "subject", Value: subject}, {Key: "user_id", Value: bson.D{{Key: "$exists", Value: false}}}},
			bson.D{{Key: "$set", Value: bson.D{{Key: "user_id", Value: userID}}}})
		if err != nil {
			return updated, err
		}
		updated += res.ModifiedCount
	}
	return updated, nil
}

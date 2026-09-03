// Command backfill-audit-fields stamps the platform audit fields (PADR-0001) on auth-api's
// pre-convention documents in user_roles and service_deny_entries: it renames the legacy
// camelCase createdAt to created_at, and sets created_by / updated_by / updated_at. No acting
// user was recorded historically, so *_by is set to the "system" sentinel; updated_at mirrors
// created_at (these rows are only ever added or removed, never updated in place).
//
// user_roles and service_deny_entries are hard-delete security-control records (PADR-0027) -
// there is no deleted_at / deleted_by pair to backfill. The retained "who revoked this" record
// is the admin_action_audit_logs collection, not touched here.
//
// Idempotent - a document that already has created_at is skipped. Dry run by default.
//
//	go run ./cmd/backfill-audit-fields          # report counts, write nothing
//	go run ./cmd/backfill-audit-fields -apply   # perform the writes
package main

import (
	"context"
	"flag"
	"time"

	"github.com/joho/godotenv"
	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/common.go/logging"
	"github.com/sweetrpg/mongodb.go/database"
	"go.mongodb.org/mongo-driver/bson"
)

const systemActor = "system"

func main() {
	apply := flag.Bool("apply", false, "perform writes (default: dry run)")
	flag.Parse()

	_ = godotenv.Load(".env")
	logging.Init()

	database.SetupDatabase()
	defer database.TeardownDatabase()

	ctx := context.Background()
	mode := "DRY RUN"
	if *apply {
		mode = "APPLY"
	}

	roles := stamp(ctx, constants.UserRolesCollection, *apply)
	deny := stamp(ctx, constants.ServiceDenyEntriesCollection, *apply)

	logging.Logger.Info("backfill-audit-fields done", "mode", mode, "user_roles", roles, "service_deny_entries", deny)
}

// stamp backfills every doc in coll whose created_at is missing: created_at from the legacy
// createdAt (or now), updated_at = created_at, created_by / updated_by = "system". Also unsets
// the legacy createdAt key.
func stamp(ctx context.Context, coll string, apply bool) int {
	filter := bson.D{{Key: "created_at", Value: bson.D{{Key: "$exists", Value: false}}}}
	cur, err := database.Db.Collection(coll).Find(ctx, filter)
	if err != nil {
		logging.Logger.Error("query failed", "collection", coll, "error", err.Error())
		return 0
	}
	var docs []bson.Raw
	if err := cur.All(ctx, &docs); err != nil {
		logging.Logger.Error("cursor read failed", "collection", coll, "error", err.Error())
		return 0
	}
	n := 0
	for _, d := range docs {
		createdAt := time.Now().UTC()
		if t, ok := d.Lookup("createdAt").TimeOK(); ok {
			createdAt = t
		}
		if !apply {
			n++
			continue
		}
		_, err := database.Db.Collection(coll).UpdateOne(ctx,
			bson.D{{Key: "_id", Value: d.Lookup("_id")}},
			bson.D{
				{Key: "$set", Value: bson.D{
					{Key: "created_at", Value: createdAt},
					{Key: "created_by", Value: systemActor},
					{Key: "updated_at", Value: createdAt},
					{Key: "updated_by", Value: systemActor},
				}},
				{Key: "$unset", Value: bson.D{{Key: "createdAt", Value: ""}}},
			})
		if err != nil {
			logging.Logger.Error("update failed", "collection", coll, "error", err.Error())
			continue
		}
		n++
	}
	return n
}

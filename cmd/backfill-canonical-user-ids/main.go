// Command backfill-canonical-user-ids rewrites auth-api's audit *_by fields from raw
// Auth0 subjects to canonical users._id (or the "system" sentinel for unresolvable subjects).
// Targets:
//   - user_roles: created_by, updated_by
//   - service_deny_entries: created_by, updated_by
//   - admin_action_audit_logs: acting_user_id (was actingUserSub)
//
// Does NOT touch:
//   - user_roles.subject, service_deny_entries.subject (these are the authorized identity)
//   - admin_action_audit_logs.targetSubject (the identity being authorized)
//
// Idempotent: skips values that are already 24-hex UUIDs or "system". Dry run by default.
//
//	go run ./cmd/backfill-canonical-user-ids          # report counts, write nothing
//	go run ./cmd/backfill-canonical-user-ids -apply   # perform the writes
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/joho/godotenv"
	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/common.go/logging"
	"github.com/sweetrpg/common.go/util"
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

	usersBaseURL := util.GetEnv(constants.USERS_API_URL, "")
	if usersBaseURL == "" {
		logging.Logger.Error("USERS_API_URL not configured, cannot resolve subjects")
		return
	}

	internalToken := util.GetEnv(constants.INTERNAL_SERVICE_TOKEN, "")
	if internalToken == "" {
		logging.Logger.Error("INTERNAL_SERVICE_TOKEN not configured, cannot call users-api")
		return
	}

	roles := backfillUserRoles(ctx, usersBaseURL, internalToken, *apply)
	deny := backfillServiceDenyEntries(ctx, usersBaseURL, internalToken, *apply)
	audit := backfillAdminActionAuditLogs(ctx, usersBaseURL, internalToken, *apply)

	logging.Logger.Info("backfill-canonical-user-ids done", "mode", mode, "user_roles", roles, "service_deny_entries", deny, "admin_action_audit_logs", audit)
}

func backfillUserRoles(ctx context.Context, usersBaseURL, internalToken string, apply bool) int {
	return backfillCollection(ctx, constants.UserRolesCollection, []string{"created_by", "updated_by"}, usersBaseURL, internalToken, apply)
}

func backfillServiceDenyEntries(ctx context.Context, usersBaseURL, internalToken string, apply bool) int {
	return backfillCollection(ctx, constants.ServiceDenyEntriesCollection, []string{"created_by", "updated_by"}, usersBaseURL, internalToken, apply)
}

func backfillAdminActionAuditLogs(ctx context.Context, usersBaseURL, internalToken string, apply bool) int {
	return backfillAuditLogs(ctx, usersBaseURL, internalToken, apply)
}

func backfillCollection(ctx context.Context, coll string, byFields []string, usersBaseURL, internalToken string, apply bool) int {
	// Find docs where any byField is a subject (not a UUID or "system")
	// We'll fetch all docs and filter in Go for simplicity, since these collections are small.
	filter := bson.D{}
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

	// Collect all distinct subject-shaped values
	subjectSet := make(map[string]struct{})
	for _, d := range docs {
		for _, field := range byFields {
			if val, ok := d.Lookup(field).StringValueOK(); ok && isSubject(val) {
				subjectSet[val] = struct{}{}
			}
		}
	}

	if len(subjectSet) == 0 {
		logging.Logger.Info("no subjects to resolve", "collection", coll)
		return 0
	}

	// Resolve all subjects in one batch
	subjects := make([]string, 0, len(subjectSet))
	for s := range subjectSet {
		subjects = append(subjects, s)
	}
	resolved, err := resolveSubjects(ctx, usersBaseURL, internalToken, subjects)
	if err != nil {
		logging.Logger.Error("resolve failed", "collection", coll, "error", err.Error())
		return 0
	}

	n := 0
	for _, d := range docs {
		id := d.Lookup("_id")
		setFields := bson.D{}
		for _, field := range byFields {
			if val, ok := d.Lookup(field).StringValueOK(); ok && isSubject(val) {
				if uid, ok := resolved[val]; ok {
					setFields = append(setFields, bson.E{Key: field, Value: uid})
				} else {
					setFields = append(setFields, bson.E{Key: field, Value: systemActor})
				}
			}
		}
		if len(setFields) == 0 {
			continue
		}
		if !apply {
			n++
			continue
		}
		_, err := database.Db.Collection(coll).UpdateOne(ctx,
			bson.D{{Key: "_id", Value: id}},
			bson.D{{Key: "$set", Value: setFields}},
		)
		if err != nil {
			logging.Logger.Error("update failed", "collection", coll, "id", id, "error", err.Error())
			continue
		}
		n++
	}
	return n
}

func backfillAuditLogs(ctx context.Context, usersBaseURL, internalToken string, apply bool) int {
	filter := bson.D{}
	cur, err := database.Db.Collection(constants.AdminActionAuditLogCollection).Find(ctx, filter)
	if err != nil {
		logging.Logger.Error("query failed", "collection", constants.AdminActionAuditLogCollection, "error", err.Error())
		return 0
	}
	var docs []bson.Raw
	if err := cur.All(ctx, &docs); err != nil {
		logging.Logger.Error("cursor read failed", "collection", constants.AdminActionAuditLogCollection, "error", err.Error())
		return 0
	}

	subjectSet := make(map[string]struct{})
	for _, d := range docs {
		// actingUserSub field in old docs, acting_user_id in new
		if val, ok := d.Lookup("actingUserSub").StringValueOK(); ok && isSubject(val) {
			subjectSet[val] = struct{}{}
		}
		// Also check acting_user_id in case some were already migrated
		if val, ok := d.Lookup("acting_user_id").StringValueOK(); ok && isSubject(val) {
			subjectSet[val] = struct{}{}
		}
	}

	if len(subjectSet) == 0 {
		logging.Logger.Info("no actingUserSub subjects to resolve")
		return 0
	}

	subjects := make([]string, 0, len(subjectSet))
	for s := range subjectSet {
		subjects = append(subjects, s)
	}
	resolved, err := resolveSubjects(ctx, usersBaseURL, internalToken, subjects)
	if err != nil {
		logging.Logger.Error("resolve failed", "collection", constants.AdminActionAuditLogCollection, "error", err.Error())
		return 0
	}

	n := 0
	for _, d := range docs {
		id := d.Lookup("_id")
		var setFields bson.D
		// Check both old and new field names
		if val, ok := d.Lookup("actingUserSub").StringValueOK(); ok && isSubject(val) {
			if uid, ok := resolved[val]; ok {
				setFields = append(setFields, bson.E{Key: "acting_user_id", Value: uid})
			} else {
				setFields = append(setFields, bson.E{Key: "acting_user_id", Value: systemActor})
			}
			// Also unset the old field
			setFields = append(setFields, bson.E{Key: "$unset", Value: bson.D{{Key: "actingUserSub", Value: ""}}})
		} else if val, ok := d.Lookup("acting_user_id").StringValueOK(); ok && isSubject(val) {
			if uid, ok := resolved[val]; ok {
				setFields = append(setFields, bson.E{Key: "acting_user_id", Value: uid})
			} else {
				setFields = append(setFields, bson.E{Key: "acting_user_id", Value: systemActor})
			}
		}

		if len(setFields) == 0 {
			continue
		}
		if !apply {
			n++
			continue
		}
		_, err := database.Db.Collection(constants.AdminActionAuditLogCollection).UpdateOne(ctx,
			bson.D{{Key: "_id", Value: id}},
			bson.D{{Key: "$set", Value: setFields}},
		)
		if err != nil {
			logging.Logger.Error("update failed", "collection", constants.AdminActionAuditLogCollection, "id", id, "error", err.Error())
			continue
		}
		n++
	}
	return n
}

func isSubject(val string) bool {
	// Auth0 subjects are not 24-hex and not "system"
	if val == systemActor {
		return false
	}
	if len(val) == 24 {
		// Check if all hex
		for i := 0; i < 24; i++ {
			c := val[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return true // not all hex, treat as subject
			}
		}
		return false // 24-hex UUID, already canonical
	}
	return true // treat as subject
}

func resolveSubjects(ctx context.Context, usersBaseURL, internalToken string, subjects []string) (map[string]string, error) {
	type resolveRequest struct {
		Subjects []string `json:"subjects"`
	}
	type resolveResponse map[string]string

	body, err := json.Marshal(resolveRequest{Subjects: subjects})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, usersBaseURL+"/internal/resolve-subjects", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+internalToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from users-api", resp.StatusCode)
	}

	var out resolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

package models

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/mongodb.go/database"
	"go.mongodb.org/mongo-driver/bson"
)

// Roles follow the person: a role held under one linked login applies to the other, a deny entry
// too, and removing it through either login removes it for both.
func TestRolesAndDenyEntriesFollowTheUserAcrossLinkedLogins(t *testing.T) {
	ctx := context.Background()
	run := fmt.Sprintf("%d", time.Now().UnixNano())
	user := "user-" + run
	first := Principal{Subject: "google-oauth2|" + run, UserID: user}
	second := Principal{Subject: "github|" + run, UserID: user}
	t.Cleanup(func() {
		_, _ = database.Db.Collection(constants.UserRolesCollection).DeleteMany(ctx, bson.D{{Key: "user_id", Value: user}})
		_, _ = database.Db.Collection(constants.ServiceDenyEntriesCollection).DeleteMany(ctx, bson.D{{Key: "user_id", Value: user}})
	})

	if err := AddRole(ctx, first, RoleAdmin, "tester"); err != nil {
		t.Fatal(err)
	}
	if err := AddDenyEntry(ctx, first, "catalog-api", "tester"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := HasRole(ctx, second, RoleAdmin); !ok {
		t.Error("the second login should hold the admin role")
	}
	if ok, _ := HasDenyEntry(ctx, second, "catalog-api"); !ok {
		t.Error("the second login should be denied too")
	}
	if rows, _ := ListRolesFor(ctx, second); len(rows) != 1 {
		t.Errorf("roles = %d, want 1", len(rows))
	}
	if err := RemoveRole(ctx, second, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if ok, _ := HasRole(ctx, first, RoleAdmin); ok {
		t.Error("removing through the second login should remove it for the first")
	}
}

func TestBackfillSetsUserIDOnLegacyRowsOnce(t *testing.T) {
	ctx := context.Background()
	run := fmt.Sprintf("%d", time.Now().UnixNano())
	known, unknown := "auth0|known-"+run, "auth0|unknown-"+run
	t.Cleanup(func() {
		_, _ = database.Db.Collection(constants.UserRolesCollection).DeleteMany(ctx, bson.D{{Key: "subject", Value: bson.D{{Key: "$in", Value: bson.A{known, unknown}}}}})
	})
	for _, s := range []string{known, unknown} {
		if err := AddRole(ctx, Principal{Subject: s}, RoleAdmin, "tester"); err != nil {
			t.Fatal(err)
		}
	}
	resolve := func(_ context.Context, subjects []string) (map[string]string, error) {
		out := map[string]string{}
		for _, s := range subjects {
			if s == known {
				out[s] = "user-" + run
			}
		}
		return out, nil
	}
	if _, err := BackfillUserIDs(ctx, resolve); err != nil {
		t.Fatal(err)
	}
	var doc UserRole
	if err := database.Db.Collection(constants.UserRolesCollection).FindOne(ctx, bson.D{{Key: "subject", Value: known}}).Decode(&doc); err != nil || doc.UserID != "user-"+run {
		t.Errorf("known subject's row: user_id = %q, err %v", doc.UserID, err)
	}
	var unresolved UserRole
	if err := database.Db.Collection(constants.UserRolesCollection).FindOne(ctx, bson.D{{Key: "subject", Value: unknown}}).Decode(&unresolved); err != nil || unresolved.UserID != "" {
		t.Errorf("unknown subject's row: user_id = %q, err %v", unresolved.UserID, err)
	}
	// the matching row follows the person from a login the backfill never saw
	if ok, _ := HasRole(ctx, Principal{Subject: "other|" + run, UserID: "user-" + run}, RoleAdmin); !ok {
		t.Error("a sibling login should inherit the backfilled role")
	}
}

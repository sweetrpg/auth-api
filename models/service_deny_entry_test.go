package models

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/common.go/logging"
	"github.com/sweetrpg/mongodb.go/database"
	"go.mongodb.org/mongo-driver/bson"
)

// TestMain connects to the DB_URI-configured MongoDB (a CI service container, see
// .github/workflows/{ci,pr}.yaml). DB-backed tests skip entirely without DB_URI so a local
// `go test ./...` still passes offline.
func TestMain(m *testing.M) {
	if os.Getenv("DB_URI") == "" {
		fmt.Println("DB_URI not set, skipping auth-api models DB-backed tests")
		os.Exit(0)
	}
	logging.Init()
	database.SetupDatabase()
	os.Exit(m.Run())
}

func addDenyFixture(t *testing.T, subject, service string) {
	t.Helper()
	if err := AddDenyEntry(context.Background(), subject, service, "test-actor"); err != nil {
		t.Fatalf("seed deny entry %s/%s: %v", subject, service, err)
	}
	t.Cleanup(func() {
		_, _ = database.Db.Collection(constants.ServiceDenyEntriesCollection).
			DeleteMany(context.Background(), bson.D{{Key: "subject", Value: subject}})
	})
}

func TestCountRestrictedSubjects_EmptyIsZero(t *testing.T) {
	ctx := context.Background()
	// Isolate from any rows other tests may have left mid-run.
	_, _ = database.Db.Collection(constants.ServiceDenyEntriesCollection).DeleteMany(ctx, bson.D{})

	got, err := CountRestrictedSubjects(ctx)
	if err != nil {
		t.Fatalf("CountRestrictedSubjects: %v", err)
	}
	if got != 0 {
		t.Errorf("CountRestrictedSubjects on empty collection = %d, want 0", got)
	}
}

func TestCountRestrictedSubjects_CountsDistinctSubjects(t *testing.T) {
	ctx := context.Background()
	_, _ = database.Db.Collection(constants.ServiceDenyEntriesCollection).DeleteMany(ctx, bson.D{})

	run := fmt.Sprintf("%d", time.Now().UnixNano())
	subjectA := "auth0|deny-stats-a-" + run
	subjectB := "auth0|deny-stats-b-" + run

	// subjectA denied two services, subjectB one - three rows, two distinct subjects.
	addDenyFixture(t, subjectA, "catalog-api")
	addDenyFixture(t, subjectA, "game-systems-api")
	addDenyFixture(t, subjectB, "catalog-api")

	got, err := CountRestrictedSubjects(ctx)
	if err != nil {
		t.Fatalf("CountRestrictedSubjects: %v", err)
	}
	if got != 2 {
		t.Errorf("CountRestrictedSubjects = %d, want 2 (subjectA's two entries count once)", got)
	}
}

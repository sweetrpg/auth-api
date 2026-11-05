// Command backfill-user-ids sets user_id on user_roles and service_deny_entries rows that were
// written keyed by Auth0 subject only, so roles and deny entries follow the person across linked
// logins. Idempotent: rows that already have a user_id, and subjects users-api does not know, are
// left alone.
//
// Runs as an administrator (PADR-0037): put an admin user's bearer token in ADMIN_BEARER_TOKEN,
// the same token the sweetrpg CLI uses. Needs DB_* (or DB_URI) and USERS_API_URL.
//
//	ADMIN_BEARER_TOKEN=... go run ./cmd/backfill-user-ids
package main

import (
	"context"
	"os"

	"github.com/joho/godotenv"
	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/auth-api/identity"
	"github.com/sweetrpg/auth-api/models"
	"github.com/sweetrpg/common.go/logging"
	"github.com/sweetrpg/common.go/util"
	"github.com/sweetrpg/mongodb.go/database"
)

func main() {
	_ = godotenv.Load(".env")
	logging.Init()

	token := util.GetEnv(constants.ADMIN_BEARER_TOKEN, "")
	baseURL := util.GetEnv(constants.USERS_API_URL, "")
	if token == "" || baseURL == "" {
		logging.Logger.Error("ADMIN_BEARER_TOKEN and USERS_API_URL are required")
		os.Exit(1)
	}

	database.SetupDatabase()
	defer database.TeardownDatabase()

	resolver := identity.New(baseURL, nil)
	n, err := models.BackfillUserIDs(context.Background(), func(ctx context.Context, subjects []string) (map[string]string, error) {
		return resolver.Resolve(ctx, subjects, token)
	})
	if err != nil {
		logging.Logger.Error("backfill failed", "error", err.Error())
		os.Exit(1)
	}
	logging.Logger.Info("backfill-user-ids done", "rows_updated", n)
}

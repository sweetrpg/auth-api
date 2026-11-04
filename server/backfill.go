package server

import (
	"context"
	"time"

	"github.com/sweetrpg/auth-api/models"
	"github.com/sweetrpg/common.go/logging"
)

// BackfillUserIDsInBackground sets user_id on role and deny rows that were written keyed by login
// only, so they follow the person across linked logins. It runs once at startup, retries while
// users-api is unreachable, and does nothing once every resolvable row has a user_id. Rows whose
// subject users-api does not know yet are picked up by a later start.
func BackfillUserIDsInBackground() {
	go func() {
		for attempt := 1; attempt <= 5; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			n, err := models.BackfillUserIDs(ctx, userResolver.Resolve)
			cancel()
			if err == nil {
				if n > 0 {
					logging.Logger.Info("set user_id on legacy role and deny rows", "rows", n)
				}
				return
			}
			logging.Logger.Warn("user id backfill failed; will retry", "attempt", attempt, "error", err.Error())
			time.Sleep(time.Duration(attempt) * 30 * time.Second)
		}
		logging.Logger.Error("user id backfill gave up; legacy rows still match by subject only")
	}()
}

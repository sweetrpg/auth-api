package server

import (
	"context"

	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/auth-api/identity"
	"github.com/sweetrpg/auth-api/models"
	"github.com/sweetrpg/common.go/util"
)

// userResolver maps a login to its canonical user, so roles and deny entries follow the person
// across linked logins. Set by setupRolesHandlers; nil resolves nothing (subject-only matching).
var userResolver *identity.Resolver

func newUserResolver() *identity.Resolver {
	return identity.New(util.GetEnv(constants.USERS_API_URL, ""), util.GetEnv(constants.INTERNAL_SERVICE_TOKEN, ""))
}

// principal returns who subject is for role and deny lookups: the login plus its canonical user
// when users-api knows it.
func principal(ctx context.Context, subject string) models.Principal {
	return models.Principal{Subject: subject, UserID: userResolver.UserID(ctx, subject)}
}

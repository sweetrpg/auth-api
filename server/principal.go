package server

import (
	"context"

	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/auth-api/identity"
	"github.com/sweetrpg/auth-api/models"
	"github.com/sweetrpg/authz-client.go/authz"
	"github.com/sweetrpg/common.go/util"
)

// userResolver maps a login to its canonical user, so roles and deny entries follow the person
// across linked logins. Nil resolves nothing (subject-only matching).
var userResolver *identity.Resolver

// ensureUserResolver builds the resolver once. Lookups use user bearer tokens only (PADR-0037).
func ensureUserResolver() {
	if userResolver != nil {
		return
	}
	usersBaseURL := util.GetEnv(constants.USERS_API_URL, "")
	userResolver = identity.New(usersBaseURL, authz.NewClient("", usersBaseURL).ResolveUserID)
}

// ownPrincipal is the caller's own login plus the canonical user their own bearer token resolves
// to (users-api GET /profile, cached). token may be empty, which leaves the subject alone.
func ownPrincipal(ctx context.Context, subject, token string) models.Principal {
	return models.Principal{Subject: subject, UserID: userResolver.Own(ctx, subject, token)}
}

// cachedPrincipal uses only an already cached answer, never the network. /authz/check uses it
// for users-api itself: users-api answers GET /profile by calling /authz/check, so resolving
// there would loop.
func cachedPrincipal(subject string) models.Principal {
	return models.Principal{Subject: subject, UserID: userResolver.Cached(subject)}
}

// targetPrincipal is another user's login plus their canonical user, resolved with the acting
// administrator's bearer token. Without one (internal-token callers) it is the subject alone.
func targetPrincipal(ctx context.Context, subject, adminToken string) models.Principal {
	return models.Principal{Subject: subject, UserID: userResolver.Other(ctx, subject, adminToken)}
}

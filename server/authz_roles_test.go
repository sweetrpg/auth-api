package server

import (
	"slices"
	"testing"

	"github.com/sweetrpg/auth-api/models"
)

func rows(roles ...models.Role) []*models.UserRole {
	out := make([]*models.UserRole, 0, len(roles))
	for _, r := range roles {
		out = append(out, &models.UserRole{Role: r})
	}
	return out
}

func TestEffectiveRoles(t *testing.T) {
	cases := map[string]struct {
		in   []*models.UserRole
		want []string
	}{
		"no rows is a user":                     {nil, []string{"user"}},
		"admin only also gets user":             {rows(models.RoleAdmin), []string{"admin", "user"}},
		"admin and user does not duplicate":     {rows(models.RoleAdmin, models.RoleUser), []string{"admin", "user"}},
		"openfga-writer stays without user":     {rows(models.RoleOpenFGAWriter), []string{"openfga-writer"}},
		"editor stays without user":             {rows(models.RoleEditor), []string{"editor"}},
		"admin with another role gets user too": {rows(models.RoleEditor, models.RoleAdmin), []string{"editor", "admin", "user"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := effectiveRoles(c.in); !slices.Equal(got, c.want) {
				t.Errorf("effectiveRoles = %v, want %v", got, c.want)
			}
		})
	}
}

package registry

import "testing"

func TestRegistryHasTheExpectedServices(t *testing.T) {
	want := []string{"admin-api", "auth-api", "catalog-api", "entitlements-api", "game-room-api", "game-systems-api", "initiative-api", "users-api"}
	got := Services()
	if len(got) != len(want) {
		t.Fatalf("services = %v", got)
	}
	for i, id := range want {
		if got[i].ID != id || got[i].Name == "" || !Known(id) {
			t.Errorf("entry %d = %+v, want id %s with a name", i, got[i], id)
		}
	}
}

func TestUnknownServicesAreNotKnown(t *testing.T) {
	for _, id := range []string{"", "Catalog-API", "catalog-api ", "nope"} {
		if Known(id) {
			t.Errorf("%q should not be known", id)
		}
	}
}

func TestServicesReturnsACopy(t *testing.T) {
	s := Services()
	s[0].ID = "changed"
	if Services()[0].ID == "changed" {
		t.Error("callers can modify the registry")
	}
}

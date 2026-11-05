package models

import (
	"testing"

	"go.mongodb.org/mongo-driver/bson"
)

func TestPrincipalFilterByUserOrSubject(t *testing.T) {
	got, _ := bson.MarshalExtJSON(Principal{Subject: "auth0|a", UserID: "u1"}.filter(), true, false)
	want := `{"$or":[{"user_id":"u1"},{"subject":"auth0|a"}]}`
	if string(got) != want {
		t.Errorf("filter = %s, want %s", got, want)
	}
}

func TestPrincipalFilterWithoutAUserFallsBackToTheSubject(t *testing.T) {
	got, _ := bson.MarshalExtJSON(Principal{Subject: "auth0|a"}.filter(), true, false)
	if string(got) != `{"subject":"auth0|a"}` {
		t.Errorf("filter = %s", got)
	}
}

func TestPrincipalWithNarrowsTheFilter(t *testing.T) {
	got, _ := bson.MarshalExtJSON(Principal{Subject: "auth0|a", UserID: "u1"}.with("role", "admin"), true, false)
	want := `{"$and":[{"$or":[{"user_id":"u1"},{"subject":"auth0|a"}]},{"role":"admin"}]}`
	if string(got) != want {
		t.Errorf("filter = %s, want %s", got, want)
	}
}

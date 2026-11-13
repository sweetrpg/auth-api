package fga

import "testing"

func TestDesiredModelParsesDSL(t *testing.T) {
	req, err := desiredModel()
	if err != nil {
		t.Fatalf("desiredModel() error = %v", err)
	}
	if len(req.TypeDefinitions) == 0 {
		t.Fatal("desiredModel() returned no type definitions")
	}
	found := map[string]bool{}
	for _, td := range req.TypeDefinitions {
		found[td.Type] = true
	}
	for _, want := range []string{"user", "platform", "volume-edit", "session", "encounter"} {
		if !found[want] {
			t.Errorf("type %q missing from model", want)
		}
	}
}

func TestSameDefinitionsDetectsChange(t *testing.T) {
	a, err := desiredModel()
	if err != nil {
		t.Fatalf("desiredModel() error = %v", err)
	}
	if !sameDefinitions(a.TypeDefinitions, a.TypeDefinitions) {
		t.Error("identical definitions reported as different")
	}
	if sameDefinitions(a.TypeDefinitions, a.TypeDefinitions[:1]) {
		t.Error("truncated definitions reported as identical")
	}
}

func TestInitiativeRelations(t *testing.T) {
	req, err := desiredModel()
	if err != nil {
		t.Fatalf("desiredModel() error = %v", err)
	}
	want := map[string][]string{
		"session":   {"gm", "co_gm", "player", "observer", "can_view", "can_edit", "can_approve"},
		"encounter": {"parent", "can_view", "can_edit", "can_approve"},
	}
	for _, td := range req.TypeDefinitions {
		for _, rel := range want[td.Type] {
			if _, ok := (*td.Relations)[rel]; !ok {
				t.Errorf("%s is missing relation %q", td.Type, rel)
			}
		}
	}
}

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
	for _, want := range []string{"user", "platform", "volume-edit"} {
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

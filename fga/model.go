package fga

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	fgasdk "github.com/openfga/go-sdk"
	openfga "github.com/openfga/go-sdk/client"
	"github.com/openfga/language/pkg/go/transformer"
)

// modelDSL is the checked-in authorization model and the source of truth. The JSON form OpenFGA
// stores is derived from it at bootstrap.
//
//go:embed model.fga
var modelDSL string

// desiredModel converts the checked-in DSL into the request OpenFGA expects.
func desiredModel() (openfga.ClientWriteAuthorizationModelRequest, error) {
	var req openfga.ClientWriteAuthorizationModelRequest
	raw, err := transformer.TransformDSLToJSON(modelDSL)
	if err != nil {
		return req, fmt.Errorf("parse openfga model DSL: %w", err)
	}
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		return req, fmt.Errorf("decode openfga model JSON: %w", err)
	}
	return req, nil
}

// sameDefinitions reports whether two sets of type definitions encode identically. The SDK
// serializes both sides the same way, so byte equality matches semantic equality here.
func sameDefinitions(a, b []fgasdk.TypeDefinition) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

// Package registry lists the services a user can be denied access to. The list is data
// (services.json): add an entry when a service starts calling /authz/check.
package registry

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// Service is one registered service. ID is what the service passes to /authz/check.
type Service struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

//go:embed services.json
var raw []byte

var services = mustLoad(raw)

func mustLoad(b []byte) []Service {
	var out []Service
	if err := json.Unmarshal(b, &out); err != nil {
		panic(fmt.Sprintf("registry: services.json is invalid: %v", err))
	}
	return out
}

// Services returns the registered services in file order.
func Services() []Service { return append([]Service(nil), services...) }

// Known reports whether id is a registered service.
func Known(id string) bool {
	for _, s := range services {
		if s.ID == id {
			return true
		}
	}
	return false
}

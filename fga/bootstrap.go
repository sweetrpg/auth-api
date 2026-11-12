package fga

import (
	"context"
	"fmt"

	fgasdk "github.com/openfga/go-sdk"
	openfga "github.com/openfga/go-sdk/client"
	"github.com/sweetrpg/common.go/logging"
)

// Bootstrapped identifies the store and model the service uses.
type Bootstrapped struct {
	StoreID string
	ModelID string
}

// Bootstrap finds or creates the named store, then makes sure its latest authorization model
// matches the checked-in DSL. A model that differs gets written as a new version; an identical
// one is reused, so restarts do not pile up model versions.
func Bootstrap(ctx context.Context, apiURL, storeName string) (Bootstrapped, error) {
	admin, err := openfga.NewSdkClient(&openfga.ClientConfiguration{ApiUrl: apiURL})
	if err != nil {
		return Bootstrapped{}, fmt.Errorf("create openfga admin client: %w", err)
	}
	storeID, err := findOrCreateStore(ctx, admin, storeName)
	if err != nil {
		return Bootstrapped{}, err
	}

	scoped, err := openfga.NewSdkClient(&openfga.ClientConfiguration{ApiUrl: apiURL, StoreId: storeID})
	if err != nil {
		return Bootstrapped{}, fmt.Errorf("create openfga store client: %w", err)
	}
	modelID, err := ensureModel(ctx, scoped)
	if err != nil {
		return Bootstrapped{}, err
	}
	logging.Logger.Info("OpenFGA bootstrap complete", "store_id", storeID, "model_id", modelID)
	return Bootstrapped{StoreID: storeID, ModelID: modelID}, nil
}

// findOrCreateStore returns the named store's ID. Replicas starting together can each create one,
// so after creating it re-lists and every replica converges on the oldest store of that name
// (ties by ID); a replica whose own store lost removes it.
func findOrCreateStore(ctx context.Context, admin *openfga.OpenFgaClient, name string) (string, error) {
	existing, err := storesNamed(ctx, admin, name)
	if err != nil {
		return "", err
	}
	if len(existing) > 0 {
		return oldestStore(existing).Id, nil
	}
	created, err := admin.CreateStore(ctx).Body(openfga.ClientCreateStoreRequest{Name: name}).Execute()
	if err != nil {
		return "", fmt.Errorf("create openfga store %q: %w", name, err)
	}
	logging.Logger.Info("Created OpenFGA store", "name", name, "store_id", created.Id)

	all, err := storesNamed(ctx, admin, name)
	if err != nil {
		return "", err
	}
	if len(all) == 0 {
		return created.Id, nil
	}
	winner := oldestStore(all)
	if winner.Id != created.Id {
		if _, err := admin.DeleteStore(ctx).Options(openfga.ClientDeleteStoreOptions{StoreId: &created.Id}).Execute(); err != nil {
			logging.Logger.Warn("Failed to remove duplicate OpenFGA store", "store_id", created.Id, "error", err.Error())
		}
	}
	return winner.Id, nil
}

func storesNamed(ctx context.Context, admin *openfga.OpenFgaClient, name string) ([]fgasdk.Store, error) {
	var matches []fgasdk.Store
	token := ""
	for {
		opts := openfga.ClientListStoresOptions{}
		if token != "" {
			opts.ContinuationToken = &token
		}
		page, err := admin.ListStores(ctx).Options(opts).Execute()
		if err != nil {
			return nil, fmt.Errorf("list openfga stores: %w", err)
		}
		for _, s := range page.Stores {
			if s.Name == name {
				matches = append(matches, s)
			}
		}
		if page.ContinuationToken == "" {
			return matches, nil
		}
		token = page.ContinuationToken
	}
}

// oldestStore picks the store every replica agrees on. stores must not be empty.
func oldestStore(stores []fgasdk.Store) fgasdk.Store {
	best := stores[0]
	for _, s := range stores[1:] {
		if s.CreatedAt.Before(best.CreatedAt) || (s.CreatedAt.Equal(best.CreatedAt) && s.Id < best.Id) {
			best = s
		}
	}
	return best
}

func ensureModel(ctx context.Context, scoped *openfga.OpenFgaClient) (string, error) {
	desired, err := desiredModel()
	if err != nil {
		return "", err
	}
	// A store with no model returns no error and a nil model, so any error here is a real failure
	// and must not write a new model version.
	latest, err := scoped.ReadLatestAuthorizationModel(ctx).Execute()
	if err != nil {
		return "", fmt.Errorf("read latest openfga authorization model: %w", err)
	}
	if latest.AuthorizationModel != nil && sameDefinitions(latest.AuthorizationModel.TypeDefinitions, desired.TypeDefinitions) {
		return latest.AuthorizationModel.Id, nil
	}
	written, err := scoped.WriteAuthorizationModel(ctx).Body(desired).Execute()
	if err != nil {
		return "", fmt.Errorf("write openfga authorization model: %w", err)
	}
	return written.AuthorizationModelId, nil
}

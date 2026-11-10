package fga

import (
	"context"
	"fmt"

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

func findOrCreateStore(ctx context.Context, admin *openfga.OpenFgaClient, name string) (string, error) {
	token := ""
	for {
		opts := openfga.ClientListStoresOptions{}
		if token != "" {
			opts.ContinuationToken = &token
		}
		page, err := admin.ListStores(ctx).Options(opts).Execute()
		if err != nil {
			return "", fmt.Errorf("list openfga stores: %w", err)
		}
		for _, s := range page.Stores {
			if s.Name == name {
				return s.Id, nil
			}
		}
		if page.ContinuationToken == "" {
			break
		}
		token = page.ContinuationToken
	}
	created, err := admin.CreateStore(ctx).Body(openfga.ClientCreateStoreRequest{Name: name}).Execute()
	if err != nil {
		return "", fmt.Errorf("create openfga store %q: %w", name, err)
	}
	logging.Logger.Info("Created OpenFGA store", "name", name, "store_id", created.Id)
	return created.Id, nil
}

func ensureModel(ctx context.Context, scoped *openfga.OpenFgaClient) (string, error) {
	desired, err := desiredModel()
	if err != nil {
		return "", err
	}
	latest, err := scoped.ReadLatestAuthorizationModel(ctx).Execute()
	if err == nil && latest.AuthorizationModel != nil && sameDefinitions(latest.AuthorizationModel.TypeDefinitions, desired.TypeDefinitions) {
		return latest.AuthorizationModel.Id, nil
	}
	written, err := scoped.WriteAuthorizationModel(ctx).Body(desired).Execute()
	if err != nil {
		return "", fmt.Errorf("write openfga authorization model: %w", err)
	}
	return written.AuthorizationModelId, nil
}

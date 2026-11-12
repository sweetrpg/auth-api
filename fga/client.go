package fga

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	fgasdk "github.com/openfga/go-sdk"
	openfga "github.com/openfga/go-sdk/client"
	"github.com/sweetrpg/common.go/logging"
)

// Write failures a caller can act on. Anything else is a transport or server failure.
var (
	// ErrInvalid means OpenFGA rejected the batch: an unknown relation, a tuple that violates the
	// model, or a malformed key. Retrying the same batch cannot succeed.
	ErrInvalid = errors.New("openfga rejected the tuple batch")
	// ErrConflict means the batch conflicts with stored state (HTTP 409).
	ErrConflict = errors.New("openfga tuple batch conflicts with stored state")
)

// Tuple is one relationship: User has Relation on Object, e.g. user:alice approver volume-edit:1234.
type Tuple struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

// Store is the subset of OpenFGA the platform uses. Handlers depend on this interface so tests
// run without a server.
type Store interface {
	Check(ctx context.Context, t Tuple) (bool, error)
	Write(ctx context.Context, writes, deletes []Tuple) error
	Read(ctx context.Context, object string, pageSize int32, continuation string) ([]Tuple, string, error)
}

// Client is the OpenFGA-backed Store, bound to one store and authorization model.
type Client struct {
	sdk *openfga.OpenFgaClient
}

// NewClient builds a Client for a store and model that Bootstrap resolved.
func NewClient(apiURL, storeID, modelID string) (*Client, error) {
	sdk, err := openfga.NewSdkClient(&openfga.ClientConfiguration{
		ApiUrl:               apiURL,
		StoreId:              storeID,
		AuthorizationModelId: modelID,
	})
	if err != nil {
		return nil, fmt.Errorf("create openfga client: %w", err)
	}
	return &Client{sdk: sdk}, nil
}

// Check reports whether t.User holds t.Relation on t.Object.
func (c *Client) Check(ctx context.Context, t Tuple) (bool, error) {
	resp, err := c.sdk.Check(ctx).Body(openfga.ClientCheckRequest{
		User:     t.User,
		Relation: t.Relation,
		Object:   t.Object,
	}).Execute()
	if err != nil {
		return false, fmt.Errorf("openfga check: %w", err)
	}
	return resp.GetAllowed(), nil
}

// Write applies writes and deletes in one OpenFGA request. The SDK sends it as a single
// transaction by default, so a failure applies none of them. Writing a tuple that already exists
// and deleting one that does not are ignored, so a reconciliation can resend a batch safely.
// A rejected batch returns ErrInvalid or ErrConflict; the returned text carries no OpenFGA
// response detail because the caller stores it in the audit log.
func (c *Client) Write(ctx context.Context, writes, deletes []Tuple) error {
	body := openfga.ClientWriteRequest{
		Writes:  toClientKeys(writes),
		Deletes: toClientDeletes(deletes),
	}
	opts := openfga.ClientWriteOptions{Conflict: openfga.ClientWriteConflictOptions{
		OnDuplicateWrites: openfga.CLIENT_WRITE_REQUEST_ON_DUPLICATE_WRITES_IGNORE,
		OnMissingDeletes:  openfga.CLIENT_WRITE_REQUEST_ON_MISSING_DELETES_IGNORE,
	}}
	if _, err := c.sdk.Write(ctx).Body(body).Options(opts).Execute(); err != nil {
		logging.Logger.Error("OpenFGA write failed", "error", err.Error())
		return classifyWriteError(err)
	}
	return nil
}

func classifyWriteError(err error) error {
	var validation fgasdk.FgaApiValidationError
	if errors.As(err, &validation) {
		return fmt.Errorf("%w: %s", ErrInvalid, validation.ResponseCode())
	}
	var api fgasdk.FgaApiError
	if errors.As(err, &api) && api.ResponseStatusCode() == http.StatusConflict {
		return ErrConflict
	}
	return errors.New("openfga write failed")
}

// Read returns one page of tuples on object and the continuation token for the next page, empty
// when there are no more.
func (c *Client) Read(ctx context.Context, object string, pageSize int32, continuation string) ([]Tuple, string, error) {
	opts := openfga.ClientReadOptions{PageSize: &pageSize}
	if continuation != "" {
		opts.ContinuationToken = &continuation
	}
	resp, err := c.sdk.Read(ctx).Body(openfga.ClientReadRequest{Object: &object}).Options(opts).Execute()
	if err != nil {
		return nil, "", fmt.Errorf("openfga read: %w", err)
	}
	tuples := make([]Tuple, 0, len(resp.Tuples))
	for _, t := range resp.Tuples {
		key := t.GetKey()
		tuples = append(tuples, Tuple{User: key.GetUser(), Relation: key.GetRelation(), Object: key.GetObject()})
	}
	return tuples, resp.GetContinuationToken(), nil
}

func toClientKeys(ts []Tuple) []openfga.ClientTupleKey {
	if len(ts) == 0 {
		return nil
	}
	keys := make([]openfga.ClientTupleKey, 0, len(ts))
	for _, t := range ts {
		keys = append(keys, openfga.ClientTupleKey{User: t.User, Relation: t.Relation, Object: t.Object})
	}
	return keys
}

func toClientDeletes(ts []Tuple) []openfga.ClientTupleKeyWithoutCondition {
	if len(ts) == 0 {
		return nil
	}
	keys := make([]openfga.ClientTupleKeyWithoutCondition, 0, len(ts))
	for _, t := range ts {
		keys = append(keys, openfga.ClientTupleKeyWithoutCondition{User: t.User, Relation: t.Relation, Object: t.Object})
	}
	return keys
}

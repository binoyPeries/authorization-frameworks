package opa

import (
	"context"
	_ "embed"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

//go:embed opa.rego
var policyContent string

type Client struct {
	preparedQuery rego.PreparedEvalQuery
	store         storage.Store
	mu            sync.RWMutex
}

func NewClient(ctx context.Context) (*Client, error) {
	store := inmem.New()

	query, err := rego.New(
		rego.Query("data.choreo.authz.allow"),
		rego.Module("authz.rego", policyContent),
		rego.Store(store),
	).PrepareForEval(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to prepare query: %w", err)
	}

	return &Client{
		preparedQuery: query,
		store:         store,
	}, nil
}

func (c *Client) IsAllowed(ctx context.Context, req AuthzRequest) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	results, err := c.preparedQuery.Eval(ctx, rego.EvalInput(req))
	if err != nil {
		return false, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	if len(results) == 0 {
		return false, nil
	}

	allowed, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return false, fmt.Errorf("unexpected result type")
	}

	return allowed, nil
}

// LoadData loads roles and role bindings into OPA.
// This is typically called at startup to populate the authorization data.
//
// Note: We don't need to load group membership data since groups are provided
// directly in each authorization request from the authentication layer.
//
// Parameters:
//   - roles: Set of roles with their permissions
//   - bindings: Role bindings that map IDPGroup → Role → Resource scope
func (c *Client) LoadData(ctx context.Context, roles []Role, bindings []RoleBinding) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	txn, err := c.store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return err
	}

	// Load roles (set of permissions)
	if err := c.store.Write(ctx, txn, storage.AddOp,
		storage.MustParsePath("/roles"), roles); err != nil {
		c.store.Abort(ctx, txn)
		return err
	}

	// Load role bindings (IDPGroup → Role → Resource scope mappings)
	if err := c.store.Write(ctx, txn, storage.AddOp,
		storage.MustParsePath("/role_bindings"), bindings); err != nil {
		c.store.Abort(ctx, txn)
		return err
	}

	if err := c.store.Commit(ctx, txn); err != nil {
		return err
	}

	return nil
}

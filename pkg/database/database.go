// Package database provides a public API for OPA Control Plane database operations.
//
// This package wraps the internal database layer, exposing Bundle, Source, and
// Source Data CRUD operations using JSON ([]byte) as the data boundary. This
// follows the same pattern as pkg/gitsync and pkg/httpsync: external consumers
// pass generic data types, and the wrapper handles serialization internally.
//
// Example usage:
//
//	db := database.New()
//	db.WithAuthorizer(myAuthorizer)
//	rawConfig := []byte(`{"database": {"sql": {"driver": "sqlite3", "dsn": "file::memory:?cache=shared"}}}`)
//	if err := db.InitDB(ctx, rawConfig); err != nil {
//	    log.Fatal(err)
//	}
//	defer db.CloseDB()
//
//	// Upsert a bundle from JSON
//	bundleJSON := []byte(`{"name": "my-bundle", "requirements": [{"source": "my-source"}]}`)
//	if err := db.UpsertBundle(ctx, "admin", "default", bundleJSON); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Get a bundle as JSON
//	data, err := db.GetBundle(ctx, "admin", "default", "my-bundle")
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"iter"

	jp "github.com/evanphx/json-patch/v5"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	internaldatabase "github.com/open-policy-agent/opa-control-plane/internal/database"
	ext_authz "github.com/open-policy-agent/opa-control-plane/pkg/authz"
)

// Re-export sentinel errors.
var (
	ErrNotFound      = internaldatabase.ErrNotFound
	ErrNotAuthorized = internaldatabase.ErrNotAuthorized
)

// ErrInvalidJSON indicates the provided JSON could not be deserialized into the expected type.
var ErrInvalidJSON = errors.New("invalid JSON")

// invalidJSON wraps an unmarshalling error with ErrInvalidJSON so callers can
// use errors.Is(err, ErrInvalidJSON) to detect malformed input.
func invalidJSON(typeName string, err error) error {
	return fmt.Errorf("%w: failed to decode %s: %v", ErrInvalidJSON, typeName, err)
}

// Database wraps the internal database layer, providing a JSON-based API
// for external consumers.
type Database struct {
	db *internaldatabase.Database
}

// New creates a new Database instance with default configuration.
func New() *Database {
	return &Database{db: internaldatabase.New()}
}

// WithAuthorizer sets the authorizer for permission checks.
func (d *Database) WithAuthorizer(a ext_authz.Authorizer) *Database {
	d.db = d.db.WithAuthorizer(a)
	return d
}

// WithAccessFactory sets the factory for creating access descriptors.
func (d *Database) WithAccessFactory(af ext_authz.AccessFactory) *Database {
	d.db = d.db.WithAccessFactory(af)
	return d
}

// InitDB initializes the database connection from a raw root configuration.
//
// The rawConfig must be a JSON (or YAML) document containing a "database" key.
// Example:
//
//	{"database": {"sql": {"driver": "sqlite3", "dsn": "file::memory:?cache=shared"}}}
func (d *Database) InitDB(ctx context.Context, rawConfig []byte) error {
	d.db = d.db.WithRawRootConfig(rawConfig)
	return d.db.InitDB(ctx)
}

// CloseDB closes the underlying database connection.
func (d *Database) CloseDB() {
	d.db.CloseDB()
}

// DB returns the underlying *sql.DB for use with migration tooling.
func (d *Database) DB() *sql.DB {
	return d.db.DB()
}

// Dialect returns the SQL dialect name ("sqlite", "postgresql", "mysql", "cockroachdb").
func (d *Database) Dialect() (string, error) {
	return d.db.Dialect()
}

// Bundle CRUD

// GetBundle retrieves a bundle by name and returns it as JSON.
func (d *Database) GetBundle(ctx context.Context, principal, tenant, name string) ([]byte, error) {
	bundle, err := d.db.GetBundle(ctx, principal, tenant, name)
	if err != nil {
		return nil, err
	}
	return json.Marshal(bundle)
}

// ListBundles lists bundles for a tenant, returning a JSON array and the next cursor.
func (d *Database) ListBundles(ctx context.Context, principal, tenant string, limit int, cursor string) ([]byte, string, error) {
	bundles, nextCursor, err := d.db.ListBundles(ctx, principal, tenant, internaldatabase.ListOptions{
		Limit:  limit,
		Cursor: cursor,
	})
	if err != nil {
		return nil, "", err
	}
	data, err := json.Marshal(bundles)
	if err != nil {
		return nil, "", err
	}
	return data, nextCursor, nil
}

// UpsertBundle creates or updates a bundle from JSON.
//
// The JSON must contain at least a "name" field. See internal/config.Bundle for the full schema.
func (d *Database) UpsertBundle(ctx context.Context, principal, tenant string, bundleJSON []byte) error {
	var bundle config.Bundle
	if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
		return invalidJSON("bundle", err)
	}
	if bundle.Name == "" {
		return invalidJSON("bundle", errors.New("name is required"))
	}
	return d.db.UpsertBundle(ctx, principal, tenant, &bundle)
}

// DeleteBundle deletes a bundle by name.
func (d *Database) DeleteBundle(ctx context.Context, principal, tenant, name string) error {
	return d.db.DeleteBundle(ctx, principal, tenant, name)
}

// Source CRUD

// GetSource retrieves a source by name and returns it as JSON.
func (d *Database) GetSource(ctx context.Context, principal, tenant, name string) ([]byte, error) {
	source, err := d.db.GetSource(ctx, principal, tenant, name)
	if err != nil {
		return nil, err
	}
	return json.Marshal(source)
}

// ListSources lists sources for a tenant, returning a JSON array and the next cursor.
func (d *Database) ListSources(ctx context.Context, principal, tenant string, limit int, cursor string) ([]byte, string, error) {
	sources, nextCursor, err := d.db.ListSources(ctx, principal, tenant, internaldatabase.ListOptions{
		Limit:  limit,
		Cursor: cursor,
	})
	if err != nil {
		return nil, "", err
	}
	data, err := json.Marshal(sources)
	if err != nil {
		return nil, "", err
	}
	return data, nextCursor, nil
}

// UpsertSource creates or updates a source from JSON.
//
// The JSON must contain at least a "name" field. See internal/config.Source for the full schema.
func (d *Database) UpsertSource(ctx context.Context, principal, tenant string, sourceJSON []byte) error {
	var source config.Source
	if err := json.Unmarshal(sourceJSON, &source); err != nil {
		return invalidJSON("source", err)
	}
	if source.Name == "" {
		return invalidJSON("source", errors.New("name is required"))
	}
	return d.db.UpsertSource(ctx, principal, tenant, &source)
}

// DeleteSource deletes a source by name.
func (d *Database) DeleteSource(ctx context.Context, principal, tenant, name string) error {
	return d.db.DeleteSource(ctx, principal, tenant, name)
}

// Source Data CRUD

// SourcesDataGet retrieves source data at the given path.
// Returns the data, whether it was found, and any error.
func (d *Database) SourcesDataGet(ctx context.Context, sourceName, path, principal, tenant string) (any, bool, error) {
	return d.db.SourcesDataGet(ctx, sourceName, path, principal, tenant)
}

// SourcesDataPut stores source data at the given path.
func (d *Database) SourcesDataPut(ctx context.Context, sourceName, path string, data any, principal, tenant string) error {
	return d.db.SourcesDataPut(ctx, sourceName, path, data, principal, tenant)
}

// SourcesDataPatch applies a JSON Patch (RFC 6902) to source data at the given path.
// The patchJSON must be a valid JSON Patch array.
func (d *Database) SourcesDataPatch(ctx context.Context, sourceName, path, principal, tenant string, patchJSON []byte) error {
	patch, err := jp.DecodePatch(patchJSON)
	if err != nil {
		return invalidJSON("json patch", err)
	}
	return d.db.SourcesDataPatch(ctx, sourceName, path, principal, tenant, patch)
}

// SourcesDataDelete deletes source data at the given path.
func (d *Database) SourcesDataDelete(ctx context.Context, sourceName, path, principal, tenant string) error {
	return d.db.SourcesDataDelete(ctx, sourceName, path, principal, tenant)
}

// Utility

// Tenants iterates over all tenant names in the database.
func (d *Database) Tenants(ctx context.Context) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		for tenant, err := range d.db.Tenants(ctx) {
			if !yield(tenant.Name, err) {
				return
			}
		}
	}
}

// UpsertPrincipal creates or updates a principal (user/service account).
func (d *Database) UpsertPrincipal(ctx context.Context, id, role, tenant string) error {
	return d.db.UpsertPrincipal(ctx, internaldatabase.Principal{
		Id:     id,
		Role:   role,
		Tenant: tenant,
	})
}

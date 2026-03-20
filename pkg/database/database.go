// Package database provides a public API for OPA Control Plane database operations.
//
// This package wraps the internal database layer, exposing Bundle, Source, and
// Source Data CRUD operations using typed config structs. External consumers
// work directly with config.Bundle and config.Source types.
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
//	// Upsert a bundle
//	bundle := &config.Bundle{Name: "my-bundle", Requirements: config.Requirements{{Source: ptr("my-source")}}}
//	if err := db.UpsertBundle(ctx, "admin", "default", bundle); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Get a bundle
//	b, err := db.GetBundle(ctx, "admin", "default", "my-bundle")
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"iter"

	jp "github.com/evanphx/json-patch/v5"

	internaldatabase "github.com/open-policy-agent/opa-control-plane/internal/database"
	ext_authz "github.com/open-policy-agent/opa-control-plane/pkg/authz"
	"github.com/open-policy-agent/opa-control-plane/pkg/config"
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

// Database wraps the internal database layer, providing a typed API
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

// GetBundle retrieves a bundle by name.
func (d *Database) GetBundle(ctx context.Context, principal, tenant, name string) (*config.Bundle, error) {
	return d.db.GetBundle(ctx, principal, tenant, name)
}

// ListBundles lists bundles for a tenant, returning the bundles and the next cursor.
func (d *Database) ListBundles(ctx context.Context, principal, tenant string, limit int, cursor string) ([]*config.Bundle, string, error) {
	return d.db.ListBundles(ctx, principal, tenant, internaldatabase.ListOptions{
		Limit:  limit,
		Cursor: cursor,
	})
}

// UpsertBundle creates or updates a bundle.
func (d *Database) UpsertBundle(ctx context.Context, principal, tenant string, bundle *config.Bundle) error {
	if bundle.Name == "" {
		return errors.New("bundle name is required")
	}
	return d.db.UpsertBundle(ctx, principal, tenant, bundle)
}

// DeleteBundle deletes a bundle by name.
func (d *Database) DeleteBundle(ctx context.Context, principal, tenant, name string) error {
	return d.db.DeleteBundle(ctx, principal, tenant, name)
}

// Source CRUD

// GetSource retrieves a source by name.
func (d *Database) GetSource(ctx context.Context, principal, tenant, name string) (*config.Source, error) {
	return d.db.GetSource(ctx, principal, tenant, name)
}

// ListSources lists sources for a tenant, returning the sources and the next cursor.
func (d *Database) ListSources(ctx context.Context, principal, tenant string, limit int, cursor string) ([]*config.Source, string, error) {
	return d.db.ListSources(ctx, principal, tenant, internaldatabase.ListOptions{
		Limit:  limit,
		Cursor: cursor,
	})
}

// UpsertSource creates or updates a source.
func (d *Database) UpsertSource(ctx context.Context, principal, tenant string, source *config.Source) error {
	if source.Name == "" {
		return errors.New("source name is required")
	}
	return d.db.UpsertSource(ctx, principal, tenant, source)
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

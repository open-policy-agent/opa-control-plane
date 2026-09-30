package sync

import (
	"context"
	"encoding/json"
	"log/slog"
)

// SourceProvider provides a type of source content, configured through a
// source's `providers:` entries. For example, an entry
//
//	providers:
//	  - name: users
//	    type: my-source
//	    param1: value
//
// is handled by the SourceProvider whose Type() is "my-source".
type SourceProvider interface {
	// Type returns the value of `type:` that selects this provider. It must
	// be unique within a registry.
	Type() string

	// ConfigSchema returns the JSON Schema (an object schema) for the entry's
	// type-specific fields, i.e. everything but the reserved keys `name`,
	// `type` and `path`, which OCP handles. It describes the configuration
	// for documentation and schema-based validation; Parse remains the
	// authoritative check.
	ConfigSchema() json.RawMessage

	// Parse validates the entry's type-specific fields (the entry without its
	// reserved keys) and returns the parsed configuration, which is passed
	// back to New as ProviderParams.Config. It is called when configuration
	// is loaded or updated, before anything is synchronized, and should
	// reject unknown fields.
	Parse(raw json.RawMessage) (any, error)

	// New creates the Synchronizer for one entry.
	New(ctx context.Context, p ProviderParams) (Synchronizer, error)
}

// ProviderParams are the parameters for creating the Synchronizer of one
// `providers:` entry.
type ProviderParams struct {
	// SourceName is the name of the source the entry belongs to.
	SourceName string

	// Name is the entry's `name:`, unique within the source.
	Name string

	// Config is the value Parse returned for the entry.
	Config any

	// Dir is the directory the Synchronizer writes the entry's content to.
	// No other entry writes to it. It exists and is empty whenever Execute
	// is called, so Execute must write all of the entry's content every time.
	// It is empty when the Synchronizer is only created to check access (see
	// AccessChecker).
	Dir string

	// SecretProvider resolves secrets for the tenant. It may be nil.
	SecretProvider SecretProvider

	// MetadataFields are the metadata fields the revision template may use.
	// Fields not listed can be skipped.
	MetadataFields []string

	// Logger is the logger to use.
	Logger *slog.Logger
}

// BundleContributor is an optional interface a Synchronizer created by a
// SourceProvider may implement to contribute to the bundle beyond the files
// it writes to its directory.
type BundleContributor interface {
	// Contribution is called after each successful Execute, and must
	// describe the content Execute left in the directory.
	Contribution(ctx context.Context) (BundleContribution, error)
}

// BundleContribution is what an entry contributes to the bundle beyond its
// files.
type BundleContribution struct {
	// Metadata is merged into the bundle manifest's metadata. A top-level key
	// contributed by two sources of the same bundle is a build error.
	Metadata map[string]any

	// Roots are bundle roots the entry claims, in manifest form (e.g.
	// "authz/main"), even if its directory has no files under them. They
	// are subject to requirement mounts and overlap checks like roots
	// computed from files.
	Roots []string

	// RegoVersion (0 or 1) sets how the entry's policies are parsed. If any
	// source of a bundle is v1, the bundle is v1. Nil leaves the default.
	RegoVersion *int
}

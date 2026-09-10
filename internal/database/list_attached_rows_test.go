package database_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	internal_config "github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
	"github.com/open-policy-agent/opa-control-plane/internal/test/dbs"
	"github.com/open-policy-agent/opa-control-plane/pkg/config"
)

// TestListAttachedRows covers the attached rows of a bundle and a source now
// that they load in statements of their own rather than through joins: the
// requirements arrive exactly once each, and the storage credentials still land
// on the bundle even though a separate statement fetches them.
//
// It also pins down the multiplication the joins made possible. Their result was
// one row per secret times requirement, and the requirement rows were appended
// per result row while only the first secret was applied. Today at most one
// secret row can match -- UpsertBundle writes one, under whichever of the three
// mutually exclusive storage backends is configured -- so the fan-out never
// happened in practice. Keyed lookups remove the possibility rather than relying
// on that.
func TestListAttachedRows(t *testing.T) {
	ctx := t.Context()

	const (
		tenant    = "fanout"
		principal = "internal:fanout"
	)

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				t.Cleanup(databaseConfig.Cleanup(t, ctr))
			}

			db, err := migrations.New().WithConfig(databaseConfig.Database(t, ctr).Database).WithMigrate(true).Run(ctx)
			require.NoError(t, err)
			t.Cleanup(db.CloseDB)

			require.NoError(t, db.UpsertTenantWithPrincipal(ctx, tenant, principal, "administrator"))

			// Three sources to require, and a secret for the bundle's storage.
			for _, name := range []string{"req-one", "req-two", "req-three"} {
				require.NoError(t, db.UpsertSource(ctx, principal, tenant, &config.Source{
					Name: name,
					Git:  config.Git{Repo: "https://example.com/" + name},
				}))
			}
			require.NoError(t, db.UpsertSecret(ctx, principal, tenant, &internal_config.Secret{
				Name:  "storage-creds",
				Value: map[string]any{"type": "aws", "access_key_id": "k", "secret_access_key": "s"},
			}))

			require.NoError(t, db.UpsertBundle(ctx, principal, tenant, &config.Bundle{
				Name: "many",
				ObjectStorage: config.ObjectStorage{
					AmazonS3: &config.AmazonS3{
						Region:      "us-east-1",
						Bucket:      "b",
						Key:         "k",
						Credentials: &config.SecretRef{Name: "storage-creds"},
					},
				},
				Requirements: []config.Requirement{
					{Source: strPtr("req-one")},
					{Source: strPtr("req-two")},
					{Source: strPtr("req-three")},
				},
			}))

			bundle, err := db.GetBundle(ctx, principal, tenant, "many")
			require.NoError(t, err)

			require.Len(t, bundle.Requirements, 3, "one entry per requirement, not one per requirement times secret")
			names := make([]string, 0, len(bundle.Requirements))
			for _, r := range bundle.Requirements {
				require.NotNil(t, r.Source)
				names = append(names, *r.Source)
			}
			assert.ElementsMatch(t, []string{"req-one", "req-two", "req-three"}, names)

			require.NotNil(t, bundle.ObjectStorage.AmazonS3, "the storage backend survives the split load")
			assert.Equal(t, "storage-creds", bundle.ObjectStorage.AmazonS3.Credentials.Name,
				"credentials are attached even though they load in a separate statement")

			// A source with several requirements has the same shape.
			require.NoError(t, db.UpsertSource(ctx, principal, tenant, &config.Source{
				Name: "requiring",
				Git:  config.Git{Repo: "https://example.com/requiring"},
				Requirements: []config.Requirement{
					{Source: strPtr("req-one")},
					{Source: strPtr("req-two")},
				},
			}))

			source, err := db.GetSource(ctx, principal, tenant, "requiring")
			require.NoError(t, err)
			require.Len(t, source.Requirements, 2)
			srcNames := make([]string, 0, len(source.Requirements))
			for _, r := range source.Requirements {
				require.NotNil(t, r.Source)
				srcNames = append(srcNames, *r.Source)
			}
			assert.ElementsMatch(t, []string{"req-one", "req-two"}, srcNames)
		})
	}
}

func strPtr(s string) *string { return &s }

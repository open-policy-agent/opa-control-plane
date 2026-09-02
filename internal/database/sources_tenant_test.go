package database_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
	"github.com/open-policy-agent/opa-control-plane/internal/test/dbs"
	"github.com/open-policy-agent/opa-control-plane/pkg/config"
)

// TestListSourcesTenantScopesDatasources covers the tenant scoping of the
// datasource load in ListSources/GetSource. Source names are only unique per
// tenant (sources has UNIQUE(tenant_id, name)), so two tenants can each own a
// source called "shared"; the datasources attached to one must never appear on
// the other's.
func TestListSourcesTenantScopesDatasources(t *testing.T) {
	ctx := t.Context()

	const sharedName = "shared"

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

			// Two tenants, each with a same-named source carrying a datasource
			// only it should ever see.
			for _, tn := range []struct{ tenant, principal, datasource string }{
				{"tenant-a", "internal:tenant-a", "ds-a"},
				{"tenant-b", "internal:tenant-b", "ds-b"},
			} {
				require.NoError(t, db.UpsertTenantWithPrincipal(ctx, tn.tenant, tn.principal, "administrator"))
				require.NoError(t, db.UpsertSource(ctx, tn.principal, tn.tenant, &config.Source{
					Name: sharedName,
					Git:  config.Git{Repo: "https://example.com/" + tn.tenant},
					Datasources: config.Datasources{{
						Name: tn.datasource,
						Path: tn.datasource,
						Type: "http",
					}},
				}))
			}

			// Sanity check: both tenants really do have a source under the same
			// name, otherwise this test would pass without exercising anything.
			var sources int
			require.NoError(t, db.DB().QueryRowContext(ctx,
				"SELECT COUNT(*) FROM sources WHERE name = 'shared'").Scan(&sources))
			require.Equal(t, 2, sources)

			for _, tc := range []struct{ tenant, principal, want string }{
				{"tenant-a", "internal:tenant-a", "ds-a"},
				{"tenant-b", "internal:tenant-b", "ds-b"},
			} {
				t.Run(tc.tenant, func(t *testing.T) {
					src, err := db.GetSource(ctx, tc.principal, tc.tenant, sharedName)
					require.NoError(t, err)

					got := make([]string, 0, len(src.Datasources))
					for _, ds := range src.Datasources {
						got = append(got, ds.Name)
					}
					assert.Equal(t, []string{tc.want}, got,
						"%s must see only its own datasource, not the same-named source's in another tenant", tc.tenant)
				})
			}
		})
	}
}

package database_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	"github.com/open-policy-agent/opa-control-plane/internal/database"
	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
	"github.com/open-policy-agent/opa-control-plane/internal/test/dbs"
	"github.com/open-policy-agent/opa-control-plane/pkg/config"
)

func TestSourceProviders(t *testing.T) {
	ctx := t.Context()
	admin := principal.Id

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
			require.NoError(t, db.UpsertPrincipal(ctx, principal))

			get := func(t *testing.T, name string) config.Providers {
				t.Helper()
				src, err := db.GetSource(ctx, admin, tenant, name)
				require.NoError(t, err)
				return src.Providers
			}
			check := func(t *testing.T, exp, got config.Providers) {
				t.Helper()
				if diff := cmp.Diff(exp, got); diff != "" {
					t.Errorf("providers (-want,+got):\n%s", diff)
				}
			}

			users := config.Provider{
				Name: "users",
				Type: "example.custom-source",
				Path: "some/prefix",
				Config: map[string]any{
					"port":   float64(8080),
					"tags":   []any{"a", "b"},
					"nested": map[string]any{"enabled": true},
				},
			}
			minimal := config.Provider{Name: "minimal", Type: "other"}

			t.Run("round trip", func(t *testing.T) {
				require.NoError(t, db.UpsertSource(ctx, admin, tenant, &config.Source{
					Name: "app", Providers: config.Providers{users, minimal},
				}))
				// Loaded ordered by name.
				check(t, config.Providers{minimal, users}, get(t, "app"))
			})

			t.Run("entries are replaced", func(t *testing.T) {
				changed := users
				changed.Config = map[string]any{"port": float64(9090)}
				require.NoError(t, db.UpsertSource(ctx, admin, tenant, &config.Source{
					Name: "app", Providers: config.Providers{changed},
				}))
				check(t, config.Providers{changed}, get(t, "app"))
			})

			t.Run("omitted entries are kept", func(t *testing.T) {
				// A caller unaware of providers (nil) must not remove them.
				require.NoError(t, db.UpsertSource(ctx, admin, tenant, &config.Source{
					Name: "app", Git: config.Git{Repo: "https://example.com/repo.git"},
				}))
				check(t, config.Providers{{Name: "users", Type: "example.custom-source", Path: "some/prefix", Config: map[string]any{"port": float64(9090)}}}, get(t, "app"))
			})

			t.Run("empty list removes all entries", func(t *testing.T) {
				require.NoError(t, db.UpsertSource(ctx, admin, tenant, &config.Source{Name: "app", Providers: config.Providers{}}))
				check(t, nil, get(t, "app"))
			})

			t.Run("listed per source", func(t *testing.T) {
				require.NoError(t, db.UpsertSource(ctx, admin, tenant, &config.Source{
					Name: "one", Providers: config.Providers{users},
				}))
				require.NoError(t, db.UpsertSource(ctx, admin, tenant, &config.Source{
					Name: "two", Providers: config.Providers{minimal},
				}))
				sources, _, err := db.ListSources(ctx, admin, tenant, database.ListOptions{})
				require.NoError(t, err)
				got := map[string]config.Providers{}
				for _, src := range sources {
					got[src.Name] = src.Providers
				}
				check(t, config.Providers{users}, got["one"])
				check(t, config.Providers{minimal}, got["two"])
			})

			t.Run("deleted with source", func(t *testing.T) {
				require.NoError(t, db.UpsertSource(ctx, admin, tenant, &config.Source{
					Name: "gone", Providers: config.Providers{users, minimal},
				}))
				require.NoError(t, db.DeleteSource(ctx, admin, tenant, "gone"))

				var n int
				require.NoError(t, db.DB().QueryRowContext(ctx,
					"SELECT COUNT(*) FROM sources_providers JOIN sources ON sources.id = sources_providers.source_id WHERE sources.name = 'gone'").Scan(&n))
				require.Equal(t, 0, n)
				var orphans int
				require.NoError(t, db.DB().QueryRowContext(ctx,
					"SELECT COUNT(*) FROM sources_providers WHERE source_id NOT IN (SELECT id FROM sources)").Scan(&orphans))
				require.Equal(t, 0, orphans)
			})
		})
	}
}

// TestListSourcesTenantScopesProviders mirrors
// TestListSourcesTenantScopesDatasources for provider entries.
func TestListSourcesTenantScopesProviders(t *testing.T) {
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

			for _, tn := range []struct{ tenant, principal, provider string }{
				{"tenant-a", "internal:tenant-a", "p-a"},
				{"tenant-b", "internal:tenant-b", "p-b"},
			} {
				require.NoError(t, db.UpsertTenantWithPrincipal(ctx, tn.tenant, tn.principal, "administrator"))
				require.NoError(t, db.UpsertSource(ctx, tn.principal, tn.tenant, &config.Source{
					Name:      sharedName,
					Providers: config.Providers{{Name: tn.provider, Type: "t"}},
				}))
			}

			for _, tc := range []struct{ tenant, principal, want string }{
				{"tenant-a", "internal:tenant-a", "p-a"},
				{"tenant-b", "internal:tenant-b", "p-b"},
			} {
				t.Run(tc.tenant, func(t *testing.T) {
					src, err := db.GetSource(ctx, tc.principal, tc.tenant, sharedName)
					require.NoError(t, err)
					require.Equal(t, config.Providers{{Name: tc.want, Type: "t"}}, src.Providers)
				})
			}
		})
	}
}

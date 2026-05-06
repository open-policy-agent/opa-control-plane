package database_test

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/open-policy-agent/opa-control-plane/internal/database"
	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
	"github.com/open-policy-agent/opa-control-plane/internal/test/dbs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/testcontainers/testcontainers-go"
)

func TestUpsertTenantWithPrincipal(t *testing.T) {
	ctx := t.Context()
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

			t.Run("creates tenant and principal", func(t *testing.T) {
				err := db.UpsertTenantWithPrincipal(ctx, "myapp", "internal:myapp", "administrator")
				require.NoError(t, err)

				var tenantName string
				err = db.DB().QueryRowContext(ctx, "SELECT name FROM tenants WHERE name = 'myapp'").Scan(&tenantName)
				require.NoError(t, err)
				assert.Equal(t, "myapp", tenantName)

				var principalID string
				err = db.DB().QueryRowContext(ctx,
					"SELECT id FROM principals WHERE id = 'internal:myapp'",
				).Scan(&principalID)
				require.NoError(t, err)
				assert.Equal(t, "internal:myapp", principalID)
			})

			t.Run("idempotent on repeated calls", func(t *testing.T) {
				err := db.UpsertTenantWithPrincipal(ctx, "myapp2", "internal:myapp2", "administrator")
				require.NoError(t, err)
				err = db.UpsertTenantWithPrincipal(ctx, "myapp2", "internal:myapp2", "administrator")
				require.NoError(t, err)

				var count int
				err = db.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM tenants WHERE name = 'myapp2'").Scan(&count)
				require.NoError(t, err)
				assert.Equal(t, 1, count)
			})
		})
	}
}

func TestCascadingDeletesForPrincipalsAndResourcePermissions(t *testing.T) {
	ctx := t.Context()
	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				t.Cleanup(databaseConfig.Cleanup(t, ctr))
			}

			db, err := migrations.New().WithConfig(databaseConfig.Database(t, ctr).Database).WithMigrate(true).Run(ctx)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if _, err := db.DB().ExecContext(ctx, "INSERT INTO tenants (name) VALUES ('tenant01')"); err != nil {
				t.Fatal(err)
			}

			if err := db.UpsertPrincipal(ctx, database.Principal{Id: "test", Tenant: "tenant01", Role: "administrator"}); err != nil {
				t.Fatal(err)
			}

			var count int
			if err := db.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM resource_permissions").Scan(&count); err != nil {
				t.Fatal(err)
			} else if count != 0 {
				t.Fatal("expected count to be zero")
			}

			var tenantID int
			if err := db.DB().QueryRowContext(ctx, "SELECT id FROM tenants WHERE name = 'tenant01'").Scan(&tenantID); err != nil {
				t.Fatalf("getting tenant ID: %v", err)
			}

			for i := range 100 { // arbitrary number of perms
				if _, err := db.DB().ExecContext(ctx,
					fmt.Sprintf("INSERT INTO resource_permissions (name, resource, principal_id, role, tenant_id) VALUES ('%s', '%s', '%s', '%s', %d)", "xyz"+strconv.Itoa(i), "bundles", "test", "owner", tenantID),
				); err != nil {
					t.Fatal(err)
				}
			}

			if err := db.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM resource_permissions").Scan(&count); err != nil {
				t.Fatal(err)
			} else if count != 100 {
				t.Fatal("expected count to be 100")
			}

			if _, err := db.DB().Exec("DELETE FROM principals WHERE id ='test'"); err != nil {
				t.Fatal(err)
			}

			if err := db.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM resource_permissions").Scan(&count); err != nil {
				t.Fatal(err)
			} else if count != 0 {
				t.Fatal("expected count to be zero")
			}
		})
	}
}

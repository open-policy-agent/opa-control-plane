package database_test

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/open-policy-agent/opa-control-plane/internal/database"
	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
	"github.com/open-policy-agent/opa-control-plane/internal/test/dbs"

	"github.com/testcontainers/testcontainers-go"
)

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

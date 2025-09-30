package database_test

import (
	"strconv"
	"testing"

	"github.com/styrainc/opa-control-plane/internal/database"
	"github.com/styrainc/opa-control-plane/internal/migrations"
)

// TODO(sr): run these tests with all databases.
func TestCascadingDeletesForPrincipalsAndResourcePermissions(t *testing.T) {
	ctx := t.Context()

	db, err := migrations.New().WithMigrate(true).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.UpsertPrincipal(ctx, database.Principal{Id: "test", Role: "administrator"}); err != nil {
		t.Fatal(err)
	}

	var count int

	if err := db.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM resource_permissions").Scan(&count); err != nil {
		t.Fatal(err)
	} else if count != 0 {
		t.Fatal("expected count to be zero")
	}

	for i := range 100 { // arbitrary number of perms
		if _, err := db.DB().ExecContext(ctx, "INSERT INTO resource_permissions (name, resource, principal_id, role) VALUES (?, ?, ?, ?)", "xyz"+strconv.Itoa(i), "bundles", "test", "owner"); err != nil {
			t.Fatal(err)
		}
	}

	if err := db.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM resource_permissions").Scan(&count); err != nil {
		t.Fatal(err)
	} else if count != 100 {
		t.Fatal("expected count to be 100")
	}

	if _, err := db.DB().Exec("DELETE FROM principals WHERE id = ?", "test"); err != nil {
		t.Fatal(err)
	}

	if err := db.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM resource_permissions").Scan(&count); err != nil {
		t.Fatal(err)
	} else if count != 0 {
		t.Fatal("expected count to be zero")
	}

}

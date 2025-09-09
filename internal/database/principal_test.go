package database

import (
	"context"
	"strconv"
	"testing"
)

func TestCascadingDeletesForPrincipalsAndResourcePermissions(t *testing.T) {

	ctx := context.Background()

	var db Database
	if err := db.InitDB(ctx); err != nil {
		t.Fatal(err)
	}

	if err := db.UpsertPrincipal(ctx, Principal{Id: "test", Role: "administrator"}); err != nil {
		t.Fatal(err)
	}

	var count int

	if err := db.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM resource_permissions").Scan(&count); err != nil {
		t.Fatal(err)
	} else if count != 0 {
		t.Fatal("expected count to be zero")
	}

	for i := range 100 { // arbitrary number of perms
		if _, err := db.db.ExecContext(ctx, "INSERT INTO resource_permissions (name, resource, principal_id, role) VALUES (?, ?, ?, ?)", "xyz"+strconv.Itoa(i), "bundles", "test", "owner"); err != nil {
			t.Fatal(err)
		}
	}

	if err := db.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM resource_permissions").Scan(&count); err != nil {
		t.Fatal(err)
	} else if count != 100 {
		t.Fatal("expected count to be 100")
	}

	if _, err := db.db.Exec("DELETE FROM principals WHERE id = ?", "test"); err != nil {
		t.Fatal(err)
	}

	if err := db.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM resource_permissions").Scan(&count); err != nil {
		t.Fatal(err)
	} else if count != 0 {
		t.Fatal("expected count to be zero")
	}

}

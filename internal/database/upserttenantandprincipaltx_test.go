package database

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// UpsertTenantAndPrincipalTx is used both internally (via tx1, whose caller-opened
// tx already went through applySearchPath) and externally, by callers that open
// their own tx and hand it in directly. This pins that the external path also gets
// the configured schema's search_path applied to tx, instead of assuming the caller
// scoped it already.
//
// SQLite doesn't understand "SET LOCAL search_path", so forcing kind to cockroach
// against a SQLite-backed tx turns "the statement ran" into an observable error,
// without needing a real Postgres/CockroachDB instance.
func TestUpsertTenantAndPrincipalTx_AppliesSearchPathOnCallerOwnedTx(t *testing.T) {
	ctx := context.Background()

	rawDB, err := sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("opening sqlite: %v", err)
	}
	defer rawDB.Close()

	d := &Database{db: rawDB, executeTx: executeTx, kind: cockroach, schema: "ocp"}

	tx, err := rawDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck

	err = d.UpsertTenantAndPrincipalTx(ctx, tx, "myapp", "internal:myapp", "administrator")
	if err == nil {
		t.Fatal("expected an error from the SET LOCAL search_path statement (unsupported by SQLite); " +
			"got nil, which means UpsertTenantAndPrincipalTx did not scope tx to the configured schema")
	}
	if !strings.Contains(err.Error(), "SET") {
		t.Fatalf("expected the error to originate from the SET LOCAL search_path statement, got: %v", err)
	}
}

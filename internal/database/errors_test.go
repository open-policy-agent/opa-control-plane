package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	_ "modernc.org/sqlite"
)

func TestTranslateStoreError_Nil(t *testing.T) {
	if err := translateStoreError(nil); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestTranslateStoreError_PostgresUniqueViolation(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23505", Detail: "Key (name)=(foo) already exists."}
	err := translateStoreError(pgErr)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestTranslateStoreError_PostgresForeignKeyViolation(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23503", Detail: "Key (bundle_id)=(42) not present in table bundles."}
	err := translateStoreError(pgErr)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestTranslateStoreError_PostgresOtherError(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "42P01", Message: "relation does not exist"}
	err := translateStoreError(pgErr)
	if errors.Is(err, ErrAlreadyExists) || errors.Is(err, ErrConflict) {
		t.Fatalf("unexpected sentinel error for unrelated pg error: %v", err)
	}
	if !errors.As(err, &pgErr) {
		t.Fatalf("expected original pgErr to be preserved, got %v", err)
	}
}

func TestTranslateStoreError_MySQLDupEntry(t *testing.T) {
	myErr := &mysqldriver.MySQLError{Number: 1062, Message: "Duplicate entry 'foo' for key 'PRIMARY'"}
	err := translateStoreError(myErr)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestTranslateStoreError_MySQLForeignKey(t *testing.T) {
	myErr := &mysqldriver.MySQLError{Number: 1452, Message: "Cannot add or update a child row"}
	err := translateStoreError(myErr)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestTranslateStoreError_SQLiteUniqueConstraint(t *testing.T) {
	sqliteErr := errors.New("UNIQUE constraint failed: bundles.name, bundles.tenant_id")
	err := translateStoreError(sqliteErr)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestTranslateStoreError_SQLiteForeignKey(t *testing.T) {
	sqliteErr := errors.New("FOREIGN KEY constraint failed")
	err := translateStoreError(sqliteErr)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestTranslateStoreError_UnknownError(t *testing.T) {
	orig := errors.New("some other database error")
	err := translateStoreError(orig)
	if err != orig {
		t.Fatalf("expected original error to pass through, got %v", err)
	}
}

func TestTranslateStoreError_WrappedPgError(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23505", Detail: "Key (name)=(bar) already exists."}
	wrapped := fmt.Errorf("upsert failed: %w", pgErr)
	err := translateStoreError(wrapped)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists from wrapped pgErr, got %v", err)
	}
}

// TestLookupRequiredID_MissingRowReturnsErrInvalidReference verifies that
// looking up a row that does not exist surfaces as ErrInvalidReference rather
// than leaking the raw sql.ErrNoRows.
func TestLookupRequiredID_MissingRowReturnsErrInvalidReference(t *testing.T) {
	ctx := context.Background()
	sqlDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	for _, stmt := range []string{
		`CREATE TABLE tenants (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE)`,
		`CREATE TABLE sources (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, tenant_id INTEGER)`,
		`INSERT INTO tenants (name) VALUES ('t1')`,
	} {
		if _, err := sqlDB.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}

	d, err := NewFromDB(sqlDB, "sqlite")
	if err != nil {
		t.Fatalf("NewFromDB: %v", err)
	}

	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })

	// Sanity check: raw lookupID returns sql.ErrNoRows for a missing row.
	if _, err := d.lookupID(ctx, tx, "t1", "sources", "missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("lookupID: expected sql.ErrNoRows, got %v", err)
	}

	// lookupRequiredID must translate the missing row to ErrInvalidReference.
	_, err = d.lookupRequiredID(ctx, tx, "t1", "sources", "missing")
	if !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("lookupRequiredID: expected ErrInvalidReference, got %v", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("lookupRequiredID: must not surface sql.ErrNoRows, got %v", err)
	}
}

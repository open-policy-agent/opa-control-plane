package database

import (
	"errors"
	"fmt"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
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
	sqliteErr := fmt.Errorf("UNIQUE constraint failed: bundles.name, bundles.tenant_id")
	err := translateStoreError(sqliteErr)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestTranslateStoreError_SQLiteForeignKey(t *testing.T) {
	sqliteErr := fmt.Errorf("FOREIGN KEY constraint failed")
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

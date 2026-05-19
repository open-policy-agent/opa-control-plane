package database

import (
	"errors"
	"fmt"
	"strings"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrNotFound = errors.New("not found")
var ErrNotAuthorized = errors.New("not authorized")

// ErrAlreadyExists is returned when an insert violates a unique constraint.
var ErrAlreadyExists = errors.New("already exists")

// ErrConflict is returned when an operation conflicts with the current state
// (e.g. a foreign key constraint violation).
var ErrConflict = errors.New("conflict")

// translateStoreError maps database-driver-specific constraint errors to
// sentinel errors so callers do not need to import driver packages.
func translateStoreError(err error) error {
	if err == nil {
		return nil
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return fmt.Errorf("%w: %s", ErrAlreadyExists, pgErr.Detail)
		case "23503": // foreign_key_violation
			return fmt.Errorf("%w: %s", ErrConflict, pgErr.Detail)
		}
		return err
	}

	var myErr *mysqldriver.MySQLError
	if errors.As(err, &myErr) {
		switch myErr.Number {
		case 1062: // ER_DUP_ENTRY
			return fmt.Errorf("%w: %s", ErrAlreadyExists, myErr.Message)
		case 1451, 1452: // ER_ROW_IS_REFERENCED_2, ER_NO_REFERENCED_ROW_2
			return fmt.Errorf("%w: %s", ErrConflict, myErr.Message)
		}
		return err
	}

	// SQLite unique constraint violation (modernc.org/sqlite driver)
	msg := err.Error()
	if strings.Contains(msg, "UNIQUE constraint failed") {
		return fmt.Errorf("%w: %s", ErrAlreadyExists, msg)
	}
	if strings.Contains(msg, "FOREIGN KEY constraint failed") {
		return fmt.Errorf("%w: %s", ErrConflict, msg)
	}

	return err
}

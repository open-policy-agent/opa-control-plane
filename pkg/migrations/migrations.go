package migrations

import (
	"io/fs"

	int_migrations "github.com/open-policy-agent/opa-control-plane/internal/migrations"
)

// Migrations returns a filesystem containing SQL migration files for the specified database dialect.
// The dialect parameter determines which SQL syntax variant to use (e.g., "sqlite", "postgres", "mysql", "cockroachdb").
// This function serves as a public wrapper around the internal migrations package, providing access to
// versioned database schema migrations that can be applied using migration tools or custom migration runners.
// Returns an fs.FS containing the migration files, or an error if the dialect is unsupported.
func Migrations(dialect string) (fs.FS, error) {
	return int_migrations.Migrations(dialect)
}

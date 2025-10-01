// Package migrations is for database migrations! This is not related to
// the `opactl migrate` command at all.
package migrations

import (
	"context"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	migrate_database "github.com/golang-migrate/migrate/v4/database"
	migrate_mysql "github.com/golang-migrate/migrate/v4/database/mysql"
	migrate_postgres "github.com/golang-migrate/migrate/v4/database/postgres"
	migrate_sqlite "github.com/golang-migrate/migrate/v4/database/sqlite"
	migrate_source "github.com/golang-migrate/migrate/v4/source"
	migrate_iofs "github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/spf13/pflag"

	"github.com/styrainc/opa-control-plane/internal/config"
	"github.com/styrainc/opa-control-plane/internal/database"
	"github.com/styrainc/opa-control-plane/internal/logging"
)

type Migrator struct {
	config  *config.Database
	log     *logging.Logger
	migrate bool
}

func New() *Migrator {
	return &Migrator{}
}

func (m *Migrator) WithConfig(db *config.Database) *Migrator {
	m.config = db
	return m
}

// WithMigrate causes migrations to be applied. Without this, we will log (INFO)
// the number of pending migrations only.
func (m *Migrator) WithMigrate(yes bool) *Migrator {
	m.migrate = yes
	return m
}

func (m *Migrator) WithLogger(log *logging.Logger) *Migrator {
	m.log = log
	return m
}

func (m *Migrator) Run(ctx context.Context) (*database.Database, error) {
	db := (&database.Database{}).WithConfig(m.config).WithLogger(m.log)
	if err := db.InitDB(ctx); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	dialect, err := db.Dialect()
	if err != nil {
		return nil, err
	}

	var driver migrate_database.Driver
	switch dialect {
	case "sqlite":
		driver, err = migrate_sqlite.WithInstance(db.DB(), &migrate_sqlite.Config{})
	case "postgresql":
		driver, err = migrate_postgres.WithInstance(db.DB(), &migrate_postgres.Config{})
	case "mysql":
		driver, err = migrate_mysql.WithInstance(db.DB(), &migrate_mysql.Config{})
	default:
		// future-proofing, this shouldn't happen with the result of db.Dialect()
		err = fmt.Errorf("unknown dialect %s", dialect)
	}
	if err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	fsys, err := Migrations(dialect)
	if err != nil {
		return nil, err
	}

	d, err := migrate_iofs.New(fsys, ".")
	if err != nil {
		return nil, err
	}

	latest := findLatest(d)

	mi, err := migrate.NewWithInstance("iofs", d, dialect, driver)
	if err != nil {
		return nil, err
	}
	mi.Log = wrap{m.log}

	if !m.migrate { // log pending migrations only
		ver, _, err := mi.Version()
		switch err {
		case nil:
			switch {
			case ver == latest:
				m.log.Debug("database migrations up to date")
			case ver > latest:
				m.log.Warn("database migrations are %d steps ahead (old binary?)", ver-latest)
			case ver < latest:
				m.log.Warnf("%d database migrations pending", ver-latest)
			}
		case migrate.ErrNilVersion:
			m.log.Warn("database has never run migrations") // perhaps it's in progress, so we won't error out
		default: // some error occurred
			return nil, err
		}
		return db, nil
	}

	if err := mi.Up(); err != nil && err != migrate.ErrNoChange {
		return nil, fmt.Errorf("database migrations: %w", err)
	}
	return db, nil
}

func Var(fs *pflag.FlagSet, yes *bool) {
	fs.BoolVarP(yes, "apply-migrations", "", false, "Apply database migrations on startup")
}

func findLatest(d migrate_source.Driver) uint {
	// NB(sr): The docs seem to me misleading, and I can't find the right
	// error to use here -- so let's just return `i` on any error. It should
	// be OK given that we're only operating on an fs.FS.
	var prev uint = 0
	for next, err := d.First(); ; next, err = d.Next(prev) {
		if err != nil {
			return prev
		}
		prev = next
	}
}

// wrap wires our logger into migrate's logger. We'll log all migration-related
// messages with level DEBUG, and hardcode "verbose" to true. That way, you'll
// see no migration-related logs in standard operations, but you can see as much
// as it'll give us when using log-level debug.
type wrap struct {
	log *logging.Logger
}

func (w wrap) Printf(fmt string, args ...any) {
	w.log.Debugf(fmt, args...)
}

func (wrap) Verbose() bool {
	return true
}

package dbs

import (
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/styrainc/opa-control-plane/internal/config"
)

type Setup struct {
	Setup    func(*testing.T) testcontainers.Container
	Database func(*testing.T, testcontainers.Container) *config.Root
	Cleanup  func(*testing.T, testcontainers.Container) func()
}

func tcCleanup(t *testing.T, ctr testcontainers.Container) func() {
	return func() {
		if err := testcontainers.TerminateContainer(ctr); err != nil {
			t.Fatalf("failed to terminate container: %s", err)
		}
	}
}

// This DSN is for separating multiple in-mem SQLite instances. Each test will get
// it's own in-memory "file".
const sqliteMemoryOnlyDSNFormat = "file:%d?cache=shared&mode=memory"

// NB(sr): resetting the in-mem sqlite database between tests is surprisingly hard.
// So instead, we'll use another in-mem reference for each invocation of Database()
// for SQLite, by incrementing this counter.
var counter atomic.Int32

func memoryDBName() string {
	old := counter.Add(1)
	return fmt.Sprintf(sqliteMemoryOnlyDSNFormat, old)
}

func Configs(t *testing.T) map[string]Setup {
	t.Helper()
	return map[string]Setup{
		"sqlite-memory-only": {
			Database: func(t *testing.T, ctr testcontainers.Container) *config.Root {
				return &config.Root{
					Database: &config.Database{
						SQL: &config.SQLDatabase{
							Driver: "sqlite3",
							DSN:    memoryDBName(),
						},
					},
				}
			},
		},
		"sqlite-persistence": {
			Database: func(t *testing.T, ctr testcontainers.Container) *config.Root {
				return &config.Root{
					Database: &config.Database{
						SQL: &config.SQLDatabase{
							Driver: "sqlite3",
							DSN:    filepath.Join(t.TempDir(), "test.db"),
						},
					},
				}
			},
		},
		"postgres": {
			Setup: func(t *testing.T) testcontainers.Container {
				ctr, err := postgres.Run(
					t.Context(),
					"postgres:16-alpine",
					postgres.WithDatabase("db"),
					postgres.WithUsername("user"),
					postgres.WithPassword("password"),
					postgres.BasicWaitStrategies(),
					postgres.WithSQLDriver("pgx"),
				)
				if err != nil {
					t.Fatal("failed to start postgres container:", err)
				}
				return ctr
			},
			Cleanup: tcCleanup,
			Database: func(t *testing.T, ctr testcontainers.Container) *config.Root {
				dsn, err := ctr.(*postgres.PostgresContainer).ConnectionString(t.Context())
				if err != nil {
					t.Fatalf("failed to get postgres connection string: %v", err)
				}

				return &config.Root{
					Database: &config.Database{
						SQL: &config.SQLDatabase{
							Driver: "postgres",
							DSN:    dsn,
						},
					},
				}
			},
		},
		"mysql": {
			Setup: func(t *testing.T) testcontainers.Container {
				ctr, err := mysql.Run(t.Context(),
					"mysql:8.0",
					mysql.WithDatabase("db"),
					mysql.WithUsername("user"),
					mysql.WithPassword("password"),
				)
				if err != nil {
					t.Fatal("failed to start mysql container:", err)
				}
				return ctr
			},
			Cleanup: tcCleanup,
			Database: func(t *testing.T, ctr testcontainers.Container) *config.Root {
				dsn, err := ctr.(*mysql.MySQLContainer).ConnectionString(t.Context())
				if err != nil {
					t.Fatalf("failed to get mysql connection string: %v", err)
				}

				return &config.Root{
					Database: &config.Database{
						SQL: &config.SQLDatabase{
							Driver: "mysql",
							DSN:    dsn,
						},
					},
				}
			},
		},
	}
}

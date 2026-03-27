package database_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/database"
	"github.com/open-policy-agent/opa-control-plane/internal/logging"
	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
	"github.com/open-policy-agent/opa-control-plane/internal/test/dbs"
)

// Bundle status phases
const (
	PhaseSyncBundle  = "sync"
	PhaseBuildBundle = "build"
	PhasePushBundle  = "push"
)

// Bundle status states
const (
	StatusInProgress = "in_progress"
	StatusCompleted  = "completed"
	StatusFailed     = "failed"
)

const maxBundleStatusRetention = database.MaxBundleStatusRetention

func TestInsertBundleStatusNew(t *testing.T) {
	ctx := context.Background()

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				if databaseConfig.Cleanup != nil {
					t.Cleanup(databaseConfig.Cleanup(t, ctr))
				}
			}

			db, err := migrations.New().
				WithConfig(databaseConfig.Database(t, ctr).Database).
				WithLogger(logging.NewLogger(logging.Config{Level: logging.LevelDebug})).
				WithMigrate(true).Run(ctx)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			defer db.CloseDB()

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}

			root := config.Root{
				Bundles: map[string]*config.Bundle{
					"bundle-a": {
						Name: "bundle-a",
						Requirements: config.Requirements{
							config.Requirement{Source: newString("source-a")},
						},
					},
				},
				Sources: map[string]*config.Source{
					"source-a": {
						Name:         "source-a",
						Requirements: config.Requirements{},
					},
				},
				Database: &config.Database{
					SQL: &config.SQLDatabase{
						Driver: "sqlite3",
						DSN:    database.SQLiteMemoryOnlyDSN,
					},
				},
			}
			if err := root.Unmarshal(); err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			tests := []*testCase{
				// bootstrap environment:
				newTestCase("load config").LoadConfig(root),
				newTestCase("list bundles").ListBundles([]*config.Bundle{
					root.Bundles["bundle-a"],
				}),
			}

			for _, test := range tests {
				t.Run(test.note, func(t *testing.T) {
					for _, op := range test.operations {
						op(ctx, t, db)
					}
				})
			}

			t.Run("insert new bundle status", func(t *testing.T) {
				id, err := db.UpsertBundleStatus(ctx, tenant, "bundle-a", "rev-1", PhaseSyncBundle, StatusInProgress, "")
				require.NoError(t, err)

				// Verify the record was inserted correctly
				status, err := db.GetBundleStatus(ctx, id)
				require.NoError(t, err)
				assert.Equal(t, "rev-1", status.Revision)
				assert.Equal(t, PhaseSyncBundle, status.Phase)
				assert.Equal(t, StatusInProgress, status.Status)
				require.NotNil(t, status.ErrorMessage)
				assert.Equal(t, "", *status.ErrorMessage)
			})
		})
	}
}

func TestInsertBundleStatusMultipleSameBundleDiffRev(t *testing.T) {
	ctx := context.Background()

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				if databaseConfig.Cleanup != nil {
					t.Cleanup(databaseConfig.Cleanup(t, ctr))
				}
			}

			db, err := migrations.New().
				WithConfig(databaseConfig.Database(t, ctr).Database).
				WithLogger(logging.NewLogger(logging.Config{Level: logging.LevelDebug})).
				WithMigrate(true).Run(ctx)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			defer db.CloseDB()

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}

			root := config.Root{
				Bundles: map[string]*config.Bundle{
					"bundle-a": {
						Name: "bundle-a",
						Requirements: config.Requirements{
							config.Requirement{Source: newString("source-a")},
						},
					},
				},
				Sources: map[string]*config.Source{
					"source-a": {
						Name:         "source-a",
						Requirements: config.Requirements{},
					},
				},
				Database: &config.Database{
					SQL: &config.SQLDatabase{
						Driver: "sqlite3",
						DSN:    database.SQLiteMemoryOnlyDSN,
					},
				},
			}
			if err := root.Unmarshal(); err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			tests := []*testCase{
				// bootstrap environment:
				newTestCase("load config").LoadConfig(root),
				newTestCase("list bundles").ListBundles([]*config.Bundle{
					root.Bundles["bundle-a"],
				}),
			}

			for _, test := range tests {
				t.Run(test.note, func(t *testing.T) {
					for _, op := range test.operations {
						op(ctx, t, db)
					}
				})
			}

			t.Run("insert multiple statuses for same bundle different revisions", func(t *testing.T) {
				id1, err := db.UpsertBundleStatus(ctx, tenant, "bundle-a", "rev-1", PhaseSyncBundle, StatusInProgress, "")
				require.NoError(t, err)

				id2, err := db.UpsertBundleStatus(ctx, tenant, "bundle-a", "rev-2", PhaseBuildBundle, StatusCompleted, "")
				require.NoError(t, err)

				assert.NotEqual(t, id1, id2)

				// Both records should exist
				status1, err := db.GetBundleStatus(ctx, id1)
				require.NoError(t, err)
				assert.Equal(t, "rev-1", status1.Revision)
				assert.Equal(t, PhaseSyncBundle, status1.Phase)
				assert.Equal(t, StatusInProgress, status1.Status)

				status2, err := db.GetBundleStatus(ctx, id2)
				require.NoError(t, err)
				assert.Equal(t, "rev-2", status2.Revision)
				assert.Equal(t, PhaseBuildBundle, status2.Phase)
				assert.Equal(t, StatusCompleted, status2.Status)
			})
		})
	}
}

func TestInsertBundleStatusUpdateExisting(t *testing.T) {
	ctx := context.Background()

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				if databaseConfig.Cleanup != nil {
					t.Cleanup(databaseConfig.Cleanup(t, ctr))
				}
			}

			db, err := migrations.New().
				WithConfig(databaseConfig.Database(t, ctr).Database).
				WithLogger(logging.NewLogger(logging.Config{Level: logging.LevelDebug})).
				WithMigrate(true).Run(ctx)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			defer db.CloseDB()

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}

			root := config.Root{
				Bundles: map[string]*config.Bundle{
					"bundle-a": {
						Name: "bundle-a",
						Requirements: config.Requirements{
							config.Requirement{Source: newString("source-a")},
						},
					},
				},
				Sources: map[string]*config.Source{
					"source-a": {
						Name:         "source-a",
						Requirements: config.Requirements{},
					},
				},
				Database: &config.Database{
					SQL: &config.SQLDatabase{
						Driver: "sqlite3",
						DSN:    database.SQLiteMemoryOnlyDSN,
					},
				},
			}
			if err := root.Unmarshal(); err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			tests := []*testCase{
				// bootstrap environment:
				newTestCase("load config").LoadConfig(root),
				newTestCase("list bundles").ListBundles([]*config.Bundle{
					root.Bundles["bundle-a"],
				}),
			}

			for _, test := range tests {
				t.Run(test.note, func(t *testing.T) {
					for _, op := range test.operations {
						op(ctx, t, db)
					}
				})
			}

			t.Run("insert same tenant+bundle+revision updates existing record", func(t *testing.T) {
				// Insert first time
				id1, err := db.UpsertBundleStatus(ctx, tenant, "bundle-a", "rev-1", PhaseSyncBundle, StatusInProgress, "")
				require.NoError(t, err)

				// Insert second time with different phase/status - should update existing record
				id2, err := db.UpsertBundleStatus(ctx, tenant, "bundle-a", "rev-1", PhaseBuildBundle, StatusInProgress, "")
				require.NoError(t, err)

				// Should return the same ID
				assert.Equal(t, id1, id2)

				// Verify the record has the latest phase and status
				status, err := db.GetBundleStatus(ctx, id1)
				require.NoError(t, err)
				assert.Equal(t, PhaseBuildBundle, status.Phase)
				assert.Equal(t, StatusInProgress, status.Status)
			})
		})
	}
}

func TestGetBundleStatus(t *testing.T) {
	ctx := context.Background()

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				if databaseConfig.Cleanup != nil {
					t.Cleanup(databaseConfig.Cleanup(t, ctr))
				}
			}

			db, err := migrations.New().
				WithConfig(databaseConfig.Database(t, ctr).Database).
				WithLogger(logging.NewLogger(logging.Config{Level: logging.LevelDebug})).
				WithMigrate(true).Run(ctx)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			defer db.CloseDB()

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}

			root := config.Root{
				Bundles: map[string]*config.Bundle{
					"bundle-a": {
						Name: "bundle-a",
						Requirements: config.Requirements{
							config.Requirement{Source: newString("source-a")},
						},
					},
				},
				Sources: map[string]*config.Source{
					"source-a": {
						Name:         "source-a",
						Requirements: config.Requirements{},
					},
				},
				Database: &config.Database{
					SQL: &config.SQLDatabase{
						Driver: "sqlite3",
						DSN:    database.SQLiteMemoryOnlyDSN,
					},
				},
			}
			if err := root.Unmarshal(); err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			tests := []*testCase{
				// bootstrap environment:
				newTestCase("load config").LoadConfig(root),
				newTestCase("list bundles").ListBundles([]*config.Bundle{
					root.Bundles["bundle-a"],
				}),
			}

			for _, test := range tests {
				t.Run(test.note, func(t *testing.T) {
					for _, op := range test.operations {
						op(ctx, t, db)
					}
				})
			}

			t.Run("get existing status", func(t *testing.T) {
				id, err := db.UpsertBundleStatus(ctx, tenant, "bundle-a", "rev-1", PhaseSyncBundle, StatusCompleted, "")
				require.NoError(t, err)

				status, err := db.GetBundleStatus(ctx, id)
				require.NoError(t, err)
				assert.Equal(t, id, int(status.ID))
				assert.Equal(t, "rev-1", status.Revision)
				assert.Equal(t, PhaseSyncBundle, status.Phase)
				assert.Equal(t, StatusCompleted, status.Status)
				assert.NotZero(t, status.CreatedAt)
			})

			t.Run("get non-existent status returns ErrNotFound", func(t *testing.T) {
				_, err := db.GetBundleStatus(ctx, 999999)
				assert.ErrorIs(t, err, database.ErrNotFound)
			})

		})
	}
}

func TestUpdateBundleStatusError(t *testing.T) {
	ctx := context.Background()

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				if databaseConfig.Cleanup != nil {
					t.Cleanup(databaseConfig.Cleanup(t, ctr))
				}
			}

			db, err := migrations.New().
				WithConfig(databaseConfig.Database(t, ctr).Database).
				WithLogger(logging.NewLogger(logging.Config{Level: logging.LevelDebug})).
				WithMigrate(true).Run(ctx)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			defer db.CloseDB()

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}

			root := config.Root{
				Bundles: map[string]*config.Bundle{
					"bundle-a": {
						Name: "bundle-a",
						Requirements: config.Requirements{
							config.Requirement{Source: newString("source-a")},
						},
					},
				},
				Sources: map[string]*config.Source{
					"source-a": {
						Name:         "source-a",
						Requirements: config.Requirements{},
					},
				},
				Database: &config.Database{
					SQL: &config.SQLDatabase{
						Driver: "sqlite3",
						DSN:    database.SQLiteMemoryOnlyDSN,
					},
				},
			}
			if err := root.Unmarshal(); err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			tests := []*testCase{
				// bootstrap environment:
				newTestCase("load config").LoadConfig(root),
				newTestCase("list bundles").ListBundles([]*config.Bundle{
					root.Bundles["bundle-a"],
				}),
			}

			for _, test := range tests {
				t.Run(test.note, func(t *testing.T) {
					for _, op := range test.operations {
						op(ctx, t, db)
					}
				})
			}

			errMsg := "failed to sync bundle: connection timeout"
			id, err := db.UpsertBundleStatus(ctx, tenant, "bundle-a", "rev-1", PhaseSyncBundle, StatusFailed, errMsg)
			require.NoError(t, err)

			status, err := db.GetBundleStatus(ctx, id)
			require.NoError(t, err)
			assert.Equal(t, StatusFailed, status.Status)
			require.NotNil(t, status.ErrorMessage)
			assert.Equal(t, errMsg, *status.ErrorMessage)
		})
	}
}

func TestGetLatestBundleStatus(t *testing.T) {
	ctx := context.Background()

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				if databaseConfig.Cleanup != nil {
					t.Cleanup(databaseConfig.Cleanup(t, ctr))
				}
			}

			db, err := migrations.New().
				WithConfig(databaseConfig.Database(t, ctr).Database).
				WithLogger(logging.NewLogger(logging.Config{Level: logging.LevelDebug})).
				WithMigrate(true).Run(ctx)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			defer db.CloseDB()

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}

			root := config.Root{
				Bundles: map[string]*config.Bundle{
					"bundle-a": {
						Name: "bundle-a",
						Requirements: config.Requirements{
							config.Requirement{Source: newString("source-a")},
						},
					},
					"bundle-b": {
						Name: "bundle-b",
						Requirements: config.Requirements{
							config.Requirement{Source: newString("source-a")},
						},
					},
				},
				Sources: map[string]*config.Source{
					"source-a": {
						Name:         "source-a",
						Requirements: config.Requirements{},
					},
				},
				Database: &config.Database{
					SQL: &config.SQLDatabase{
						Driver: "sqlite3",
						DSN:    database.SQLiteMemoryOnlyDSN,
					},
				},
			}
			if err := root.Unmarshal(); err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			tests := []*testCase{
				// bootstrap environment:
				newTestCase("load config").LoadConfig(root),
				newTestCase("list bundles").ListBundles([]*config.Bundle{
					root.Bundles["bundle-a"], root.Bundles["bundle-b"],
				}),
			}

			for _, test := range tests {
				t.Run(test.note, func(t *testing.T) {
					for _, op := range test.operations {
						op(ctx, t, db)
					}
				})
			}

			t.Run("get latest status", func(t *testing.T) {
				// Insert multiple statuses with different revisions
				_, err := db.UpsertBundleStatus(ctx, tenant, "bundle-a", "rev-1", PhaseSyncBundle, StatusCompleted, "")
				require.NoError(t, err)

				_, err = db.UpsertBundleStatus(ctx, tenant, "bundle-a", "rev-2", PhaseBuildBundle, StatusInProgress, "")
				require.NoError(t, err)

				errMsg := "failed to push bundle"
				latestID, err := db.UpsertBundleStatus(ctx, tenant, "bundle-a", "rev-3", PhasePushBundle, StatusFailed, errMsg)
				require.NoError(t, err)

				// Get latest should return the most recent one
				latest, err := db.GetLatestBundleStatus(ctx, "admin", tenant, "bundle-a")
				require.NoError(t, err)
				assert.Equal(t, latestID, int(latest.ID))
				assert.Equal(t, "bundle-a", latest.BundleName)
				assert.Equal(t, "rev-3", latest.Revision)
				assert.Equal(t, PhasePushBundle, latest.Phase)
				assert.Equal(t, StatusFailed, latest.Status)
				require.NotNil(t, latest.ErrorMessage)
				assert.Equal(t, errMsg, *latest.ErrorMessage)
			})

			t.Run("get latest for non-existent bundle returns nil", func(t *testing.T) {
				latest, err := db.GetLatestBundleStatus(ctx, "admin", tenant, "bundle-x")
				assert.ErrorIs(t, err, database.ErrNotFound)
				assert.Nil(t, latest)
			})

			t.Run("get latest returns correct tenant/bundle combination", func(t *testing.T) {
				_, err := db.UpsertBundleStatus(ctx, tenant, "bundle-b", "rev-1", PhaseBuildBundle, StatusInProgress, "")
				require.NoError(t, err)

				_, err = db.UpsertBundleStatus(ctx, tenant, "bundle-a", "rev-1", PhaseSyncBundle, StatusCompleted, "")
				require.NoError(t, err)

				latestID, err := db.UpsertBundleStatus(ctx, tenant, "bundle-b", "rev-2", PhasePushBundle, StatusInProgress, "")
				require.NoError(t, err)

				// Get latest for bundle b should return bundle b's record
				latest, err := db.GetLatestBundleStatus(ctx, "admin", tenant, "bundle-b")
				require.NoError(t, err)
				assert.Equal(t, latestID, int(latest.ID))
				assert.Equal(t, "bundle-b", latest.BundleName)
				assert.Equal(t, "rev-2", latest.Revision)
				assert.Equal(t, PhasePushBundle, latest.Phase)
				assert.Equal(t, StatusInProgress, latest.Status)
			})
		})
	}
}

func TestListBundleStatuses(t *testing.T) {
	ctx := context.Background()

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				if databaseConfig.Cleanup != nil {
					t.Cleanup(databaseConfig.Cleanup(t, ctr))
				}
			}

			db, err := migrations.New().
				WithConfig(databaseConfig.Database(t, ctr).Database).
				WithLogger(logging.NewLogger(logging.Config{Level: logging.LevelDebug})).
				WithMigrate(true).Run(ctx)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			defer db.CloseDB()

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}

			root := config.Root{
				Bundles: map[string]*config.Bundle{
					"bundle-a": {
						Name: "bundle-a",
						Requirements: config.Requirements{
							config.Requirement{Source: newString("source-a")},
						},
					},
					"bundle-b": {
						Name: "bundle-b",
						Requirements: config.Requirements{
							config.Requirement{Source: newString("source-a")},
						},
					},
					"bundle-c": {
						Name: "bundle-c",
						Requirements: config.Requirements{
							config.Requirement{Source: newString("source-a")},
						},
					},
				},
				Sources: map[string]*config.Source{
					"source-a": {
						Name:         "source-a",
						Requirements: config.Requirements{},
					},
				},
				Database: &config.Database{
					SQL: &config.SQLDatabase{
						Driver: "sqlite3",
						DSN:    database.SQLiteMemoryOnlyDSN,
					},
				},
			}
			if err := root.Unmarshal(); err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			tests := []*testCase{
				// bootstrap environment:
				newTestCase("load config").LoadConfig(root),
				newTestCase("list bundles").ListBundles([]*config.Bundle{
					root.Bundles["bundle-a"], root.Bundles["bundle-b"], root.Bundles["bundle-c"],
				}),
			}

			for _, test := range tests {
				t.Run(test.note, func(t *testing.T) {
					for _, op := range test.operations {
						op(ctx, t, db)
					}
				})
			}

			t.Run("get latest status", func(t *testing.T) {
				t.Run("list all statuses for bundle", func(t *testing.T) {
					// Insert multiple statuses with different revisions
					_, err := db.UpsertBundleStatus(ctx, tenant, "bundle-a", "rev-1", PhaseSyncBundle, StatusCompleted, "")
					require.NoError(t, err)

					_, err = db.UpsertBundleStatus(ctx, tenant, "bundle-a", "rev-2", PhaseBuildBundle, StatusCompleted, "")
					require.NoError(t, err)

					_, err = db.UpsertBundleStatus(ctx, tenant, "bundle-a", "rev-3", PhasePushBundle, StatusCompleted, "")
					require.NoError(t, err)

					// List all (empty revision)
					statuses, err := db.ListBundleStatuses(ctx, "admin", tenant, "bundle-a", "", 0)
					require.NoError(t, err)
					assert.Len(t, statuses, 3)

					// Should be ordered by id (newest first)
					assert.Equal(t, "bundle-a", statuses[0].BundleName)
					assert.Equal(t, "rev-3", statuses[0].Revision)
					assert.Equal(t, "rev-2", statuses[1].Revision)
					assert.Equal(t, "rev-1", statuses[2].Revision)
				})

				t.Run("list statuses filtered by revision", func(t *testing.T) {
					// Insert status for specific revision
					_, err := db.UpsertBundleStatus(ctx, tenant, "bundle-b", "rev-1", PhaseSyncBundle, StatusCompleted, "")
					require.NoError(t, err)

					_, err = db.UpsertBundleStatus(ctx, tenant, "bundle-b", "rev-2", PhaseBuildBundle, StatusCompleted, "")
					require.NoError(t, err)

					// List filtered by revision
					statuses, err := db.ListBundleStatuses(ctx, "admin", tenant, "bundle-a", "rev-1", 0)
					require.NoError(t, err)
					assert.Len(t, statuses, 1)
					assert.Equal(t, "bundle-a", statuses[0].BundleName)
					assert.Equal(t, "rev-1", statuses[0].Revision)
				})

				t.Run("list with custom limit", func(t *testing.T) {
					// Insert 5 statuses with different revisions
					for i := range 5 {
						_, err := db.UpsertBundleStatus(ctx, tenant, "bundle-c", fmt.Sprintf("rev-%d", i), PhaseSyncBundle, StatusCompleted, "")
						require.NoError(t, err)
					}

					// List with limit of 2
					statuses, err := db.ListBundleStatuses(ctx, "admin", tenant, "bundle-c", "", 2)
					require.NoError(t, err)
					assert.Len(t, statuses, 2)
					assert.Equal(t, "bundle-c", statuses[0].BundleName)
					assert.Equal(t, "rev-4", statuses[0].Revision)
					assert.Equal(t, "rev-3", statuses[1].Revision)
				})

				t.Run("list for non-existent bundle returns empty", func(t *testing.T) {
					statuses, err := db.ListBundleStatuses(ctx, "admin", tenant, "bundle-x", "", 0)
					require.NoError(t, err)
					assert.Empty(t, statuses)
				})

			})
		})
	}
}

func TestUpsertBundleStatusRetentionCleanup(t *testing.T) {
	ctx := context.Background()

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				if databaseConfig.Cleanup != nil {
					t.Cleanup(databaseConfig.Cleanup(t, ctr))
				}
			}

			db, err := migrations.New().
				WithConfig(databaseConfig.Database(t, ctr).Database).
				WithLogger(logging.NewLogger(logging.Config{Level: logging.LevelDebug})).
				WithMigrate(true).Run(ctx)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			defer db.CloseDB()

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}

			root := config.Root{
				Bundles: map[string]*config.Bundle{
					"bundle-a": {
						Name: "bundle-a",
						Requirements: config.Requirements{
							config.Requirement{Source: newString("source-a")},
						},
					},
					"bundle-b": {
						Name: "bundle-b",
						Requirements: config.Requirements{
							config.Requirement{Source: newString("source-a")},
						},
					},
				},
				Sources: map[string]*config.Source{
					"source-a": {
						Name:         "source-a",
						Requirements: config.Requirements{},
					},
				},
				Database: &config.Database{
					SQL: &config.SQLDatabase{
						Driver: "sqlite3",
						DSN:    database.SQLiteMemoryOnlyDSN,
					},
				},
			}
			if err := root.Unmarshal(); err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			tests := []*testCase{
				newTestCase("load config").LoadConfig(root),
				newTestCase("list bundles").ListBundles([]*config.Bundle{
					root.Bundles["bundle-a"], root.Bundles["bundle-b"],
				}),
			}

			for _, test := range tests {
				t.Run(test.note, func(t *testing.T) {
					for _, op := range test.operations {
						op(ctx, t, db)
					}
				})
			}

			t.Run("keeps only last MaxBundleStatusRetention records", func(t *testing.T) {
				totalInserts := maxBundleStatusRetention + 5 // 15 total
				ids := make([]int, 0, totalInserts)

				for i := range totalInserts {
					id, err := db.UpsertBundleStatus(ctx, tenant, "bundle-a",
						fmt.Sprintf("rev-%d", i), PhaseSyncBundle, StatusInProgress, "")
					require.NoError(t, err)
					ids = append(ids, id)
				}

				// List all statuses - should be capped at MaxBundleStatusRetention
				statuses, err := db.ListBundleStatuses(ctx, "admin", tenant, "bundle-a", "", 0)
				require.NoError(t, err)
				assert.Len(t, statuses, maxBundleStatusRetention,
					"expected only %d records to be retained, got %d", maxBundleStatusRetention, len(statuses))

				// The oldest 5 records should have been deleted
				for i := range 5 {
					_, err := db.GetBundleStatus(ctx, ids[i])
					assert.ErrorIs(t, err, database.ErrNotFound,
						"expected record with id %d (rev-%d) to be deleted", ids[i], i)
				}

				// The newest MaxBundleStatusRetention records should still exist
				for i := 5; i < totalInserts; i++ {
					status, err := db.GetBundleStatus(ctx, ids[i])
					require.NoError(t, err,
						"expected record with id %d (rev-%d) to exist", ids[i], i)
					assert.Equal(t, fmt.Sprintf("rev-%d", i), status.Revision)
				}
			})

			t.Run("no cleanup when under retention limit", func(t *testing.T) {
				totalInserts := 3
				ids := make([]int, 0, totalInserts)

				for i := range totalInserts {
					id, err := db.UpsertBundleStatus(ctx, tenant, "bundle-b",
						fmt.Sprintf("rev-%d", i), PhaseSyncBundle, StatusCompleted, "")
					require.NoError(t, err)
					ids = append(ids, id)
				}

				// All records should still exist
				statuses, err := db.ListBundleStatuses(ctx, "admin", tenant, "bundle-b", "", 0)
				require.NoError(t, err)
				assert.Len(t, statuses, totalInserts)

				for i := range totalInserts {
					_, err := db.GetBundleStatus(ctx, ids[i])
					require.NoError(t, err,
						"expected record with id %d (rev-%d) to exist", ids[i], i)
				}
			})

			t.Run("retention cleanup is scoped per bundle", func(t *testing.T) {
				// Insert 3 records into bundle-b
				bundleBIDs := make([]int, 0, 3)
				for i := range 3 {
					id, err := db.UpsertBundleStatus(ctx, tenant, "bundle-b",
						fmt.Sprintf("scope-rev-%d", i), PhaseSyncBundle, StatusCompleted, "")
					require.NoError(t, err)
					bundleBIDs = append(bundleBIDs, id)
				}

				// Insert MaxBundleStatusRetention + 5 records into bundle-a to trigger cleanup
				for i := range maxBundleStatusRetention + 5 {
					_, err := db.UpsertBundleStatus(ctx, tenant, "bundle-a",
						fmt.Sprintf("scope-rev-%d", i), PhaseSyncBundle, StatusInProgress, "")
					require.NoError(t, err)
				}

				// bundle-a should have exactly MaxBundleStatusRetention records
				statuses1, err := db.ListBundleStatuses(ctx, "admin", tenant, "bundle-a", "", 0)
				require.NoError(t, err)
				assert.Len(t, statuses1, maxBundleStatusRetention)

				// bundle-b records should be unaffected by bundle-a cleanup
				for _, id := range bundleBIDs {
					_, err := db.GetBundleStatus(ctx, id)
					require.NoError(t, err,
						"bundle-b record with id %d should not be affected by bundle-a cleanup", id)
				}
			})
		})
	}
}

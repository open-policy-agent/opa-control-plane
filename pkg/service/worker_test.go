package service

import (
	"context"
	"errors"
	"testing"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/database"
	"github.com/open-policy-agent/opa-control-plane/internal/logging"
	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
	"github.com/open-policy-agent/opa-control-plane/internal/progress"
	"github.com/open-policy-agent/opa-control-plane/internal/syncerr"
	"github.com/open-policy-agent/opa-control-plane/internal/test/dbs"
)

type fakeSynchronizer struct {
	err error
}

func (f *fakeSynchronizer) Execute(context.Context) (map[string]any, error) {
	return nil, f.err
}

func (*fakeSynchronizer) Close(context.Context) {}

// TestBundleWorkerExecute_SyncError verifies that a source synchronization failure is
// reported as BuildStateUserError when the underlying error is a syncerr.UserError,
// and as BuildStateSyncFailed otherwise.
func TestBundleWorkerExecute_SyncError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expState BuildState
	}{
		{
			name:     "user error is reported as BuildStateUserError",
			err:      syncerr.UserError{Cause: errors.New("bad credentials")},
			expState: BuildStateUserError,
		},
		{
			name:     "plain error is reported as BuildStateSyncFailed",
			err:      errors.New("connection reset"),
			expState: BuildStateSyncFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			worker := NewBundleWorker(t.TempDir(), &config.Bundle{Name: "test_bundle"}, nil, nil,
				logging.NewLogger(logging.Config{}), progress.New(true, 1, "test")).
				WithSingleShot(true).
				WithSynchronizers([]sourceSynchronizer{{
					sync:       &fakeSynchronizer{err: tc.err},
					sourceName: "test-source",
					sourceType: "git",
				}})

			worker.Execute(t.Context())

			if worker.status.State != tc.expState {
				t.Fatalf("expected state %v, got %v", tc.expState, worker.status.State)
			}
		})
	}
}

// TestBundleWorkerExecute_SyncFailurePersisted verifies that a git-sync failure
// produces a queryable SYNC_FAILED status row (persisted under the pre-revision
// sentinel), proving report() centralizes the write for pre-revision phases.
func TestBundleWorkerExecute_SyncFailurePersisted(t *testing.T) {
	ctx := context.Background()

	db, err := migrations.New().
		WithConfig(&config.Database{
			SQL: &config.SQLDatabase{Driver: "sqlite3", DSN: dbs.MemoryDBName()},
		}).
		WithLogger(logging.NewLogger(logging.Config{})).
		WithMigrate(true).Run(ctx)
	if err != nil {
		t.Fatalf("failed to init database: %v", err)
	}
	defer db.CloseDB()

	const tenant = "default"
	principal := database.Principal{Id: "admin", Role: "administrator", Tenant: tenant}
	if err := db.UpsertPrincipal(ctx, principal); err != nil {
		t.Fatal(err)
	}

	sourceName := "test-source"
	root := config.Root{
		Bundles: map[string]*config.Bundle{
			"test_bundle": {
				Name:         "test_bundle",
				Requirements: config.Requirements{config.Requirement{Source: &sourceName}},
			},
		},
		Sources: map[string]*config.Source{
			"test-source": {Name: "test-source", Requirements: config.Requirements{}},
		},
		Database: &config.Database{SQL: &config.SQLDatabase{Driver: "sqlite3", DSN: database.SQLiteMemoryOnlyDSN}},
	}
	if err := root.Unmarshal(); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}
	if err := db.LoadConfig(ctx, nil, principal.Id, tenant, &root); err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	worker := NewBundleWorker(t.TempDir(), root.Bundles["test_bundle"], nil, nil,
		logging.NewLogger(logging.Config{}), progress.New(true, 1, "test")).
		WithSingleShot(true).
		WithDatabase(db).
		WithTenant(tenant).
		WithSynchronizers([]sourceSynchronizer{{
			sync:       &fakeSynchronizer{err: errors.New("connection reset")},
			sourceName: "test-source",
			sourceType: "git",
		}})

	worker.Execute(ctx)

	status, err := db.GetLatestBundleStatus(ctx, principal.Id, tenant, "test_bundle")
	if err != nil {
		t.Fatalf("expected a persisted status, got error: %v", err)
	}
	if status.Status != BuildStateSyncFailed.String() {
		t.Fatalf("expected status %q, got %q", BuildStateSyncFailed.String(), status.Status)
	}
	if status.Phase != BuildPhaseSync.String() {
		t.Fatalf("expected phase %q, got %q", BuildPhaseSync.String(), status.Phase)
	}
	if status.Revision != database.SentinelRevision {
		t.Fatalf("expected sentinel revision %q, got %q", database.SentinelRevision, status.Revision)
	}
}

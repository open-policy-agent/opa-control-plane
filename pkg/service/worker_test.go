package service

import (
	"context"
	"errors"
	"testing"
	"testing/fstest"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/database"
	"github.com/open-policy-agent/opa-control-plane/internal/logging"
	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
	"github.com/open-policy-agent/opa-control-plane/internal/progress"
	"github.com/open-policy-agent/opa-control-plane/internal/syncerr"
	"github.com/open-policy-agent/opa-control-plane/internal/test/dbs"
	"github.com/open-policy-agent/opa-control-plane/pkg/builder"
)

type fakeSynchronizer struct {
	err      error
	metadata map[string]any
}

func (f *fakeSynchronizer) Execute(context.Context) (map[string]any, error) {
	return f.metadata, f.err
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

// TestBundleWorkerExecute_CancelledBeforeReport verifies that a worker which is
// told to reconfigure/shutdown before it ever completes a build iteration is
// reported as BuildStateCancelled rather than being left at the zero-value
// BuildStateUnknown.
func TestBundleWorkerExecute_CancelledBeforeReport(t *testing.T) {
	worker := NewBundleWorker(t.TempDir(), &config.Bundle{Name: "test_bundle"}, nil, nil,
		logging.NewLogger(logging.Config{}), progress.New(true, 1, "test")).
		WithSingleShot(true)

	// Simulate the worker being told to shut down/reconfigure before Execute
	// ever runs, e.g. via Service.Run's final UpdateConfig(nil, nil, nil) call.
	worker.UpdateConfig(nil, nil, nil)

	worker.Execute(t.Context())

	if worker.status.State != BuildStateCancelled {
		t.Fatalf("expected state %v, got %v", BuildStateCancelled, worker.status.State)
	}
	if !worker.Done() {
		t.Fatal("expected worker to be done")
	}
}

// TestBundleWorkerExecute_CancelledBeforeReportPersisted verifies that a worker
// cancelled before its first report() still persists a queryable CANCELLED
// status row, instead of leaving the database with whatever the previous
// build iteration wrote (or nothing at all).
func TestBundleWorkerExecute_CancelledBeforeReportPersisted(t *testing.T) {
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

	root := config.Root{
		Bundles: map[string]*config.Bundle{
			"test_bundle": {Name: "test_bundle"},
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
		WithTenant(tenant)

	worker.UpdateConfig(nil, nil, nil)
	worker.Execute(ctx)

	status, err := db.GetLatestBundleStatus(ctx, principal.Id, tenant, "test_bundle")
	if err != nil {
		t.Fatalf("expected a persisted status, got error: %v", err)
	}
	if status.Status != BuildStateCancelled.String() {
		t.Fatalf("expected status %q, got %q", BuildStateCancelled.String(), status.Status)
	}
	if status.Revision != database.SentinelRevision {
		t.Fatalf("expected sentinel revision %q, got %q", database.SentinelRevision, status.Revision)
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

// TestBundleWorkerExecute_DuplicateDatasourceNamesDisambiguatedByPath is a
// regression test for #416/#417: two http datasources that share the same
// name but have different paths must not silently overwrite each other's
// metadata in the sourceMetadata map built by Execute. It runs the worker
// end-to-end (like a real bundle build) with two fake synchronizers for the
// same source/type/name but different paths, and verifies the resulting
// revision (computed from a template that references both datasources by
// path) reflects both, proving neither metadata entry was lost.
func TestBundleWorkerExecute_DuplicateDatasourceNamesDisambiguatedByPath(t *testing.T) {
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
	revisionTemplate := `$"{input.sources["test-source"].http.shared["/a"].hash}-{input.sources["test-source"].http.shared["/b"].hash}"`
	root := config.Root{
		Bundles: map[string]*config.Bundle{
			"test_bundle": {
				Name:         "test_bundle",
				Requirements: config.Requirements{config.Requirement{Source: &sourceName}},
				Revision:     revisionTemplate,
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

	builderSource := builder.NewSource("test-source")
	builderSource.AddFS(fstest.MapFS{})

	worker := NewBundleWorker(t.TempDir(), root.Bundles["test_bundle"], nil, nil,
		logging.NewLogger(logging.Config{}), progress.New(true, 1, "test")).
		WithSingleShot(true).
		WithDatabase(db).
		WithTenant(tenant).
		WithSources([]*builder.Source{builderSource}).
		WithSynchronizers([]sourceSynchronizer{
			{
				sync:           &fakeSynchronizer{metadata: map[string]any{"hash": "hash-a"}},
				sourceName:     "test-source",
				sourceType:     "http",
				entryName:      "shared",
				datasourcePath: "/a",
			},
			{
				sync:           &fakeSynchronizer{metadata: map[string]any{"hash": "hash-b"}},
				sourceName:     "test-source",
				sourceType:     "http",
				entryName:      "shared",
				datasourcePath: "/b",
			},
		})

	worker.Execute(ctx)

	status, err := db.GetLatestBundleStatus(ctx, principal.Id, tenant, "test_bundle")
	if err != nil {
		t.Fatalf("expected a persisted status, got error: %v", err)
	}
	if status.Status != BuildStateSuccess.String() {
		t.Fatalf("expected status %q, got %q (revision=%q)", BuildStateSuccess.String(), status.Status, status.Revision)
	}
	if want := "hash-a-hash-b"; status.Revision != want {
		t.Fatalf("expected revision %q (both datasources' metadata preserved), got %q", want, status.Revision)
	}
}

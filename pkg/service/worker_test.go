package service

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/database"
	"github.com/open-policy-agent/opa-control-plane/internal/logging"
	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
	"github.com/open-policy-agent/opa-control-plane/internal/progress"
	"github.com/open-policy-agent/opa-control-plane/internal/syncerr"
	"github.com/open-policy-agent/opa-control-plane/internal/test/dbs"
	"github.com/open-policy-agent/opa-control-plane/pkg/builder"
	ext_os "github.com/open-policy-agent/opa-control-plane/pkg/objectstorage"
)

// newTestSource builds a minimal builder.Source backed by a temp directory
// containing a single data file, sufficient for BundleWorker.Execute to run
// a real build.
func newTestSource(t *testing.T) *builder.Source {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte(`{"a":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	src := builder.NewSource("test-source")
	if err := src.AddDir(builder.Dir{Path: dir}); err != nil {
		t.Fatal(err)
	}
	return src
}

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

// fakeStorage is a plain ext_os.ObjectStorage that records how many times
// Upload was called, without implementing VersionedObjectStorage.
type fakeStorage struct {
	uploads int
}

func (f *fakeStorage) Upload(context.Context, io.ReadSeeker, ext_os.UploadOptions) error {
	f.uploads++
	return nil
}

func (*fakeStorage) Download(context.Context) (io.Reader, error) {
	return nil, errors.New("not implemented")
}

// fakeVersionedStorage additionally implements VersionedObjectStorage, so
// BundleWorker.Execute can attempt the early-skip path against it.
type fakeVersionedStorage struct {
	fakeStorage
	latestRevision string
	latestErr      error
	latestCalls    int
}

func (f *fakeVersionedStorage) LatestRevision(context.Context, ext_os.UploadOptions) (string, error) {
	f.latestCalls++
	return f.latestRevision, f.latestErr
}

// TestBundleWorkerExecute_EarlySkip verifies the early-skip path added to
// Execute: when the bundle's revision expression doesn't depend on the
// built bundle's content hash, and the storage backend reports that
// revision as already the latest stored one, Execute should short-circuit
// before ever calling Upload.
func TestBundleWorkerExecute_EarlySkip(t *testing.T) {
	t.Run("skips build and upload when resolved revision already matches", func(t *testing.T) {
		storage := &fakeVersionedStorage{latestRevision: "rev-1"}

		worker := NewBundleWorker(t.TempDir(), &config.Bundle{
			Name:     "test_bundle",
			Revision: `"rev-1"`,
		}, nil, nil, logging.NewLogger(logging.Config{}), progress.New(true, 1, "test")).
			WithSingleShot(true).
			WithStorage(storage)

		worker.Execute(t.Context())

		if storage.latestCalls != 1 {
			t.Fatalf("expected LatestRevision to be called once, got %d", storage.latestCalls)
		}
		if storage.uploads != 0 {
			t.Fatalf("expected Upload to be skipped, got %d calls", storage.uploads)
		}
		if worker.status.State != BuildStateSuccess {
			t.Fatalf("expected state %v, got %v", BuildStateSuccess, worker.status.State)
		}
	})

	t.Run("builds and uploads when resolved revision differs from latest stored", func(t *testing.T) {
		storage := &fakeVersionedStorage{latestRevision: "rev-old"}

		worker := NewBundleWorker(t.TempDir(), &config.Bundle{
			Name:     "test_bundle",
			Revision: `"rev-new"`,
		}, nil, nil, logging.NewLogger(logging.Config{}), progress.New(true, 1, "test")).
			WithSingleShot(true).
			WithSources([]*builder.Source{newTestSource(t)}).
			WithStorage(storage)

		worker.Execute(t.Context())

		if storage.latestCalls != 1 {
			t.Fatalf("expected LatestRevision to be called once, got %d", storage.latestCalls)
		}
		if storage.uploads != 1 {
			t.Fatalf("expected Upload to be called once, got %d", storage.uploads)
		}
		if worker.status.State != BuildStateSuccess {
			t.Fatalf("expected state %v, got %v", BuildStateSuccess, worker.status.State)
		}
	})

	t.Run("builds and uploads when no stored revision exists yet", func(t *testing.T) {
		storage := &fakeVersionedStorage{latestRevision: ""}

		worker := NewBundleWorker(t.TempDir(), &config.Bundle{
			Name:     "test_bundle",
			Revision: `"rev-new"`,
		}, nil, nil, logging.NewLogger(logging.Config{}), progress.New(true, 1, "test")).
			WithSingleShot(true).
			WithSources([]*builder.Source{newTestSource(t)}).
			WithStorage(storage)

		worker.Execute(t.Context())

		if storage.uploads != 1 {
			t.Fatalf("expected Upload to be called once, got %d", storage.uploads)
		}
	})

	t.Run("proceeds through normal build when LatestRevision errors", func(t *testing.T) {
		storage := &fakeVersionedStorage{latestErr: errors.New("head object failed")}

		worker := NewBundleWorker(t.TempDir(), &config.Bundle{
			Name:     "test_bundle",
			Revision: `"rev-new"`,
		}, nil, nil, logging.NewLogger(logging.Config{}), progress.New(true, 1, "test")).
			WithSingleShot(true).
			WithSources([]*builder.Source{newTestSource(t)}).
			WithStorage(storage)

		worker.Execute(t.Context())

		if storage.uploads != 1 {
			t.Fatalf("expected Upload to be called once despite LatestRevision error, got %d", storage.uploads)
		}
		if worker.status.State != BuildStateSuccess {
			t.Fatalf("expected state %v, got %v", BuildStateSuccess, worker.status.State)
		}
	})

	t.Run("does not attempt early skip when storage doesn't implement VersionedObjectStorage", func(t *testing.T) {
		storage := &fakeStorage{}

		worker := NewBundleWorker(t.TempDir(), &config.Bundle{
			Name:     "test_bundle",
			Revision: `"rev-new"`,
		}, nil, nil, logging.NewLogger(logging.Config{}), progress.New(true, 1, "test")).
			WithSingleShot(true).
			WithSources([]*builder.Source{newTestSource(t)}).
			WithStorage(storage)

		worker.Execute(t.Context())

		if storage.uploads != 1 {
			t.Fatalf("expected Upload to be called once, got %d", storage.uploads)
		}
	})

	t.Run("does not attempt early skip when revision depends on bundle content hash", func(t *testing.T) {
		storage := &fakeVersionedStorage{latestRevision: "should-be-ignored"}

		worker := NewBundleWorker(t.TempDir(), &config.Bundle{
			Name:     "test_bundle",
			Revision: `input.bundle.hash`,
		}, nil, nil, logging.NewLogger(logging.Config{}), progress.New(true, 1, "test")).
			WithSingleShot(true).
			WithSources([]*builder.Source{newTestSource(t)}).
			WithStorage(storage)

		worker.Execute(t.Context())

		if storage.latestCalls != 0 {
			t.Fatalf("expected LatestRevision not to be called, got %d calls", storage.latestCalls)
		}
		if storage.uploads != 1 {
			t.Fatalf("expected Upload to be called once, got %d", storage.uploads)
		}
	})

	t.Run("reports config error when revision expression is invalid", func(t *testing.T) {
		storage := &fakeVersionedStorage{}

		worker := NewBundleWorker(t.TempDir(), &config.Bundle{
			Name:     "test_bundle",
			Revision: "not a valid {{{ rego",
		}, nil, nil, logging.NewLogger(logging.Config{}), progress.New(true, 1, "test")).
			WithSingleShot(true).
			WithStorage(storage)

		worker.Execute(t.Context())

		if worker.status.State != BuildStateConfigError {
			t.Fatalf("expected state %v, got %v", BuildStateConfigError, worker.status.State)
		}
		if storage.uploads != 0 || storage.latestCalls != 0 {
			t.Fatalf("expected no storage interaction, got uploads=%d latestCalls=%d", storage.uploads, storage.latestCalls)
		}
	})
}

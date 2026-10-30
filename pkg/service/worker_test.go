package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
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

func TestGitManifestMetadata(t *testing.T) {
	ref, path := "main", "policies"
	syncs := []sourceSynchronizer{
		{
			sourceName: "with-all",
			sourceType: "git",
			git:        &config.Git{Repo: "https://user:secret@example.com/org/repo", Reference: &ref, Path: &path},
		},
		{sourceName: "minimal", sourceType: "git", git: &config.Git{Repo: "https://example.com/org/other"}},
		{sourceName: "not-git", sourceType: "http"},
	}
	meta := map[string]map[string]any{
		"with-all": {"git": map[string]any{"commit": "aaa"}},
		"minimal":  {"git": map[string]any{"commit": "bbb"}},
	}

	got := gitManifestMetadata(syncs, meta)
	want := map[string]any{"ocp": map[string]any{"sources": map[string]any{
		"with-all": map[string]any{"repo": "https://example.com/org/repo", "reference": "main", "commit": "aaa", "path": "policies"},
		"minimal":  map[string]any{"repo": "https://example.com/org/other", "commit": "bbb"},
	}}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("metadata (-want,+got):\n%s", diff)
	}

	if got := gitManifestMetadata(syncs[2:], meta); got != nil {
		t.Errorf("expected nil without git sources, got %v", got)
	}
}

func TestHashWithMetadata(t *testing.T) {
	meta := func(commit string) map[string]any {
		return map[string]any{"ocp": map[string]any{"sources": map[string]any{"s": map[string]any{"commit": commit}}}}
	}

	same := func(a, b string) bool { return a == b }
	h1, err := hashWithMetadata("abc", meta("c1"))
	if err != nil {
		t.Fatal(err)
	}
	h1again, _ := hashWithMetadata("abc", meta("c1"))
	h2, _ := hashWithMetadata("abc", meta("c2"))

	if !same(h1, h1again) {
		t.Error("hash is not deterministic")
	}
	if same(h1, h2) {
		t.Error("a different commit must change the hash")
	}
	if got, _ := hashWithMetadata("abc", nil); got != "abc" {
		t.Errorf("without metadata the hash must be unchanged, got %q", got)
	}
}

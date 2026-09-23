package service

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/database"
	"github.com/open-policy-agent/opa-control-plane/internal/logging"
	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
	"github.com/open-policy-agent/opa-control-plane/internal/test/dbs"
	ext_authz "github.com/open-policy-agent/opa-control-plane/pkg/authz"
)

// allowAllAuthorizer grants every access request. It isolates this test from the
// tenant-scoped rego policy (which ties a principal to a single tenant), so the
// test can focus on launchWorkers' own worker bookkeeping instead.
type allowAllAuthorizer struct{}

func (allowAllAuthorizer) Check(context.Context, *sql.Tx, ext_authz.ArgFn, ext_authz.AccessDescriptor) bool {
	return true
}

func (allowAllAuthorizer) Partial(context.Context, ext_authz.AccessDescriptor, map[string]ext_authz.SQLColumnRef) (ext_authz.Expr, error) {
	return trueExpr{}, nil
}

type trueExpr struct{}

func (trueExpr) SQL(ext_authz.ArgFn, []any) (string, []any) { return "1 = 1", nil }
func (trueExpr) Tables() []ext_authz.SQLTableRef            { return nil }

// TestLaunchWorkers_MultiTenantDoesNotCancelOtherTenants is a regression test for
// https://github.com/open-policy-agent/opa-control-plane/issues/422: onboarding a
// second tenant must not retire the workers of a tenant processed earlier in the
// same launchWorkers call.
func TestLaunchWorkers_MultiTenantDoesNotCancelOtherTenants(t *testing.T) {
	ctx := context.Background()

	db, err := migrations.New().
		WithConfig(&config.Database{
			SQL: &config.SQLDatabase{Driver: "sqlite3", DSN: dbs.MemoryDBName()},
		}).
		WithLogger(logging.NewLogger(logging.Config{})).
		WithMigrate(true).
		Run(ctx)
	if err != nil {
		t.Fatalf("failed to init database: %v", err)
	}
	defer db.CloseDB()

	db.WithAuthorizer(allowAllAuthorizer{})

	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		if _, err := db.DB().ExecContext(ctx, "INSERT INTO tenants (name) VALUES (?)", tenant); err != nil {
			t.Fatalf("failed to create tenant %q: %v", tenant, err)
		}
	}

	// A single principal row satisfies the resource_permissions foreign key for
	// every tenant; allowAllAuthorizer means its actual tenant assignment doesn't
	// matter for authorization.
	if err := db.UpsertPrincipal(ctx, database.Principal{Id: internalPrincipal, Tenant: "tenant-a", Role: "administrator"}); err != nil {
		t.Fatalf("failed to create principal: %v", err)
	}

	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		root := config.Root{
			Bundles: map[string]*config.Bundle{
				"bundle": {
					Name: "bundle",
					ObjectStorage: config.ObjectStorage{
						FileSystemStorage: &config.FileSystemStorage{Path: filepath.Join(t.TempDir(), "bundle.tar.gz")},
					},
				},
			},
		}
		if err := root.Unmarshal(); err != nil {
			t.Fatalf("failed to unmarshal config for tenant %q: %v", tenant, err)
		}
		if err := db.LoadConfig(ctx, nil, internalPrincipal, tenant, &root); err != nil {
			t.Fatalf("failed to load config for tenant %q: %v", tenant, err)
		}
	}

	// WithSingleShot makes a worker die() right after its one build instead of
	// rescheduling ~30s out, so the shutdown wait below can't land in that window.
	s := New().
		WithPersistenceDir(t.TempDir()).
		WithLogger(logging.NewLogger(logging.Config{})).
		WithSingleShot(true)
	s.database = *db

	s.launchWorkers(ctx)

	if len(s.workers) != 2 {
		t.Fatalf("expected 2 workers, got %d: %v", len(s.workers), s.workers)
	}

	for id, w := range s.workers {
		if w.configurationChanged() {
			t.Fatalf("worker %q was cancelled while launchWorkers was still processing tenants", id)
		}
	}

	for _, w := range s.workers {
		w.UpdateConfig(nil, nil, nil)
	}

	deadline := time.Now().Add(5 * time.Second)
	for !s.allWorkersDone() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for workers to shut down")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

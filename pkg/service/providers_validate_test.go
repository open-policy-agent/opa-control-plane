package service_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa-control-plane/pkg/service"
	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
)

type acceptAllProvider struct{}

func (acceptAllProvider) Type() string                           { return "example.custom-source" }
func (acceptAllProvider) ConfigSchema() json.RawMessage          { return json.RawMessage(`{}`) }
func (acceptAllProvider) Parse(raw json.RawMessage) (any, error) { return raw, nil }
func (acceptAllProvider) New(context.Context, pkgsync.ProviderParams) (pkgsync.Synchronizer, error) {
	return nil, nil
}

const providersConfig = `
sources:
  app:
    providers:
      - name: users
        type: example.custom-source
        param1: value
`

// initOnly returns a service for config, with a database of its own that is
// closed when the test ends. Tests that only call Init must not use the
// default database: it is an in-memory SQLite database shared by the whole
// test process while open, and only Run closes it.
func initOnly(t *testing.T, cfg string) *service.Service {
	t.Helper()
	dir := t.TempDir()
	db := "database:\n  sql:\n    driver: sqlite3\n    dsn: " + filepath.Join(dir, "ocp.db") + "\n"
	svc := service.New().
		WithRawConfig([]byte(db + cfg)).
		WithPersistenceDir(filepath.Join(dir, "data")).
		WithMigrateDB(true)
	t.Cleanup(func() {
		if db := svc.Database().DB(); db != nil { // nil if Init failed before opening it
			db.Close()
		}
	})
	return svc
}

func TestInitValidatesProviders(t *testing.T) {
	newService := func(t *testing.T) *service.Service {
		return initOnly(t, providersConfig)
	}

	t.Run("unknown type", func(t *testing.T) {
		err := newService(t).Init(t.Context())
		exp := `invalid configuration: source "app": provider "users": unknown type "example.custom-source"`
		if err == nil || err.Error() != exp {
			t.Fatalf("expected %q, got %v", exp, err)
		}
	})

	t.Run("registered type", func(t *testing.T) {
		svc := newService(t)
		if err := svc.SourceProviders().Register(acceptAllProvider{}); err != nil {
			t.Fatal(err)
		}
		if err := svc.Init(t.Context()); err != nil {
			t.Fatal(err)
		}
		src, err := svc.Database().GetSource(t.Context(), "internal", "default", "app")
		if err != nil {
			t.Fatal(err)
		}
		if len(src.Providers) != 1 || src.Providers[0].Name != "users" || src.Providers[0].Config["param1"] != "value" {
			t.Errorf("unexpected providers: %+v", src.Providers)
		}
	})

	t.Run("no providers", func(t *testing.T) {
		err := initOnly(t, "sources:\n  app:\n    git: {repo: https://example.com/repo.git}\n").Init(t.Context())
		if err != nil && strings.Contains(err.Error(), "invalid configuration") {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})
}

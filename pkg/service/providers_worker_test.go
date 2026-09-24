package service_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/open-policy-agent/opa/v1/bundle"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/pkg/service"
	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
)

// fileProvider writes one Rego file and one data file to its directory, and
// contributes metadata, a claimed root and Rego v1.
type fileProvider struct{}

type fileConfig struct {
	File             string `json:"file"`    // name of the Rego file to write
	Version          string `json:"version"` // returned as metadata, and written as data
	FailContribution bool   `json:"fail_contribution"`
	CheckDirWasWiped bool   `json:"check_dir_was_wiped"`
}

func (fileProvider) Type() string                  { return "example.files" }
func (fileProvider) ConfigSchema() json.RawMessage { return json.RawMessage(`{}`) }

func (fileProvider) Parse(raw json.RawMessage) (any, error) {
	var cfg fileConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (fileProvider) New(_ context.Context, p pkgsync.ProviderParams) (pkgsync.Synchronizer, error) {
	return &fileSync{cfg: p.Config.(fileConfig), dir: p.Dir}, nil
}

type fileSync struct {
	cfg fileConfig
	dir string
}

func (s *fileSync) Execute(context.Context) (map[string]any, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err // the directory must exist
	}
	if s.cfg.CheckDirWasWiped && len(entries) > 0 {
		return nil, errors.New("directory was not emptied")
	}
	rego := "package lazy.local\n\nallow if input.v == " + `"` + s.cfg.Version + `"` + "\n"
	if err := os.WriteFile(filepath.Join(s.dir, s.cfg.File), []byte(rego), 0o644); err != nil {
		return nil, err
	}
	data, _ := json.Marshal(map[string]string{"version": s.cfg.Version})
	if err := os.WriteFile(filepath.Join(s.dir, "data.json"), data, 0o644); err != nil {
		return nil, err
	}
	return map[string]any{"version": s.cfg.Version}, nil
}

func (s *fileSync) Contribution(context.Context) (pkgsync.BundleContribution, error) {
	if s.cfg.FailContribution {
		return pkgsync.BundleContribution{}, errors.New("no contribution")
	}
	return pkgsync.BundleContribution{
		Metadata:    map[string]any{"example": map[string]any{"version": s.cfg.Version}},
		Roots:       []string{"lazy/remote"},
		RegoVersion: new(1),
	}, nil
}

func (*fileSync) Close(context.Context) {}

const fileProviderConfig = `
bundles:
  b:
    object_storage:
      filesystem:
        path: {{.Out}}
    revision: input.sources.app.providers.users.version
    requirements:
    - source: app
sources:
  app:
    providers:
    - name: users
      type: example.files
      path: {{.Path}}
      file: {{.File}}
      version: {{.Version}}
      fail_contribution: {{.FailContribution}}
      check_dir_was_wiped: true
`

type fileProviderParams struct {
	Out, Path, File, Version string
	FailContribution         bool
}

// runFileProvider runs the service once (single shot) and returns its report.
func runFileProvider(t *testing.T, persistenceDir string, params fileProviderParams) *service.Report {
	t.Helper()
	cfg := fileProviderConfig
	for k, v := range map[string]string{
		"{{.Out}}": params.Out, "{{.Path}}": cmpOr(params.Path, `""`), "{{.File}}": params.File,
		"{{.Version}}": params.Version, "{{.FailContribution}}": boolString(params.FailContribution),
	} {
		cfg = strings.ReplaceAll(cfg, k, v)
	}
	root, err := config.Parse([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New().
		WithConfig(root).
		WithPersistenceDir(persistenceDir).
		WithSingleShot(true).
		WithMigrateDB(true)
	if err := svc.SourceProviders().Register(fileProvider{}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	return svc.Report()
}

func cmpOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func readBundle(t *testing.T, path string) bundle.Bundle {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := bundle.NewReader(f).Read()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func modulePaths(b bundle.Bundle) []string {
	paths := make([]string, 0, len(b.Modules))
	for _, m := range b.Modules {
		paths = append(paths, filepath.Base(m.Path))
	}
	slices.Sort(paths)
	return paths
}

func TestProviderEntryBuild(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bundle.tar.gz")

	report := runFileProvider(t, filepath.Join(dir, "data"), fileProviderParams{Out: out, Path: "pre", File: "a.rego", Version: "v1"})
	if st := report.Bundles["b"]; st.State != service.BuildStateSuccess {
		t.Fatalf("expected success, got %v: %s", st.State, st.Message)
	}

	b := readBundle(t, out)
	if got := b.Manifest.Revision; got != "v1" {
		t.Errorf("revision: expected v1 (from the entry's metadata), got %q", got)
	}
	if got := *b.Manifest.RegoVersion; got != 1 {
		t.Errorf("rego_version: expected 1, got %d", got)
	}
	if diff := cmp.Diff(map[string]any{"example": map[string]any{"version": "v1"}}, b.Manifest.Metadata); diff != "" {
		t.Errorf("metadata (-want,+got):\n%s", diff)
	}
	roots := slices.Clone(*b.Manifest.Roots)
	slices.Sort(roots)
	if diff := cmp.Diff([]string{"lazy/local", "lazy/remote", "pre"}, roots); diff != "" {
		t.Errorf("roots (-want,+got):\n%s", diff)
	}
	// The entry's path prefixes its data.
	if diff := cmp.Diff(map[string]any{"pre": map[string]any{"version": "v1"}}, b.Data); diff != "" {
		t.Errorf("data (-want,+got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"a.rego"}, modulePaths(b)); diff != "" {
		t.Errorf("modules (-want,+got):\n%s", diff)
	}
}

func TestProviderEntryDirWiped(t *testing.T) {
	// The second run uses the same persistence dir but a different file name
	// and path. Nothing from the first run may end up in the bundle; the
	// provider also fails if its directory wasn't emptied.
	dir := t.TempDir()
	persistence := filepath.Join(dir, "data")
	out := filepath.Join(dir, "bundle.tar.gz")

	for _, params := range []fileProviderParams{
		{Out: out, Path: "old", File: "a.rego", Version: "v1"},
		{Out: out, Path: "new", File: "b.rego", Version: "v2"},
	} {
		report := runFileProvider(t, persistence, params)
		if st := report.Bundles["b"]; st.State != service.BuildStateSuccess {
			t.Fatalf("%s: expected success, got %v: %s", params.Version, st.State, st.Message)
		}
	}

	b := readBundle(t, out)
	if diff := cmp.Diff([]string{"b.rego"}, modulePaths(b)); diff != "" {
		t.Errorf("modules (-want,+got):\n%s", diff)
	}
	if diff := cmp.Diff(map[string]any{"new": map[string]any{"version": "v2"}}, b.Data); diff != "" {
		t.Errorf("data (-want,+got):\n%s", diff)
	}
}

func TestProviderEntryContributionError(t *testing.T) {
	dir := t.TempDir()
	report := runFileProvider(t, filepath.Join(dir, "data"), fileProviderParams{
		Out: filepath.Join(dir, "bundle.tar.gz"), File: "a.rego", Version: "v1", FailContribution: true,
	})
	st := report.Bundles["b"]
	if st.State != service.BuildStateSyncFailed {
		t.Fatalf("expected sync failure, got %v: %s", st.State, st.Message)
	}
	if exp := `source "app": provider "users": contribution: no contribution`; !strings.Contains(st.Message, exp) {
		t.Errorf("expected message containing %q, got %q", exp, st.Message)
	}
}

func TestProviderEntryUnknownTypeFromDatabase(t *testing.T) {
	// A first service, with the provider registered, stores bundle "b" and its
	// source's entry in the database. A second service using the same
	// database doesn't register the type: bundle "b" fails with a
	// configuration error, while its other bundle still builds.
	dir := t.TempDir()
	dbConfig := `
database:
  sql:
    driver: sqlite3
    dsn: ` + filepath.Join(dir, "ocp.db") + `
`
	run := func(cfg string, register bool) *service.Report {
		t.Helper()
		root, err := config.Parse([]byte(dbConfig + cfg))
		if err != nil {
			t.Fatal(err)
		}
		svc := service.New().
			WithConfig(root).
			WithPersistenceDir(filepath.Join(dir, "data")).
			WithSingleShot(true).
			WithMigrateDB(true)
		if register {
			if err := svc.SourceProviders().Register(fileProvider{}); err != nil {
				t.Fatal(err)
			}
		}
		if err := svc.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
		return svc.Report()
	}

	first := run(`
bundles:
  b:
    object_storage: {filesystem: {path: `+filepath.Join(dir, "b.tar.gz")+`}}
    requirements: [{source: app}]
sources:
  app:
    providers:
    - {name: users, type: example.files, file: a.rego, version: v1}
`, true)
	if st := first.Bundles["b"]; st.State != service.BuildStateSuccess {
		t.Fatalf("first run: expected success, got %v: %s", st.State, st.Message)
	}

	second := run(`
bundles:
  other:
    object_storage: {filesystem: {path: `+filepath.Join(dir, "other.tar.gz")+`}}
    requirements: [{source: plain}]
sources:
  plain:
    files:
      plain.rego: `+base64.StdEncoding.EncodeToString([]byte("package plain\n\np := 1\n"))+`
`, false)
	st := second.Bundles["b"]
	if st.State != service.BuildStateConfigError {
		t.Fatalf("second run: expected configuration error for b, got %v: %s", st.State, st.Message)
	}
	if exp := `source "app": provider "users": unknown type "example.files"`; st.Message != exp {
		t.Errorf("expected message %q, got %q", exp, st.Message)
	}
	if st := second.Bundles["other"]; st.State != service.BuildStateSuccess {
		t.Errorf("second run: expected other to succeed, got %v: %s", st.State, st.Message)
	}
}

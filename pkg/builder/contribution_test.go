package builder_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/opa/bundle" // nolint:staticcheck

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/pkg/builder"
)

type contribDir struct {
	files   map[string]string
	contrib *builder.Contribution
}

type contribSource struct {
	name         string
	dirs         []contribDir
	requirements []config.Requirement
}

// buildWithContributions builds sources (the first one being the root) and
// returns the resulting bundle.
func buildWithContributions(t *testing.T, srcs []contribSource) (*bundle.Bundle, error) {
	t.Helper()
	root := t.TempDir()

	sources := make([]*builder.Source, 0, len(srcs))
	for i, src := range srcs {
		s := builder.NewSource(src.name)
		s.Requirements = src.requirements
		for j, d := range src.dirs {
			dir := filepath.Join(root, src.name, string(rune('a'+i)), string(rune('a'+j)))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			for p, content := range d.files {
				fp := filepath.Join(dir, p)
				if err := os.MkdirAll(filepath.Dir(fp), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(fp, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			dirDef := builder.Dir{Path: filepath.ToSlash(dir)}
			if d.contrib != nil {
				contrib := d.contrib
				dirDef.Contribution = func() *builder.Contribution { return contrib }
			}
			if err := s.AddDir(dirDef); err != nil {
				t.Fatal(err)
			}
		}
		sources = append(sources, s)
	}

	buf := bytes.NewBuffer(nil)
	if err := builder.New().WithSources(sources).WithOutput(buf).Build(t.Context()); err != nil {
		return nil, err
	}
	b, err := bundle.NewReader(buf).Read()
	if err != nil {
		t.Fatal(err)
	}
	return &b, nil
}

func req(name string) config.Requirement {
	return config.Requirement{Source: &name}
}

func mnt(name, path, prefix string) config.Requirement {
	return config.Requirement{Source: &name, Path: path, Prefix: prefix}
}

func checkRoots(t *testing.T, b *bundle.Bundle, exp ...string) {
	t.Helper()
	if diff := cmp.Diff(exp, *b.Manifest.Roots, cmpopts.SortSlices(strings.Compare)); diff != "" {
		t.Errorf("roots (-want,+got):\n%s", diff)
	}
}

func TestContributionRoots(t *testing.T) {
	t.Run("claimed without files", func(t *testing.T) {
		b, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{req("git"), req("provider")}},
			{name: "git", dirs: []contribDir{{files: map[string]string{"x.rego": "package app.x\np := 1"}}}},
			{name: "provider", dirs: []contribDir{{
				files:   map[string]string{"main.rego": "package authz.main\np := 1"},
				contrib: &builder.Contribution{Roots: []string{"authz/main", "lazy/loaded"}},
			}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		checkRoots(t, b, "app/x", "authz/main", "lazy/loaded")
	})

	t.Run("directory with no files", func(t *testing.T) {
		b, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{req("git"), req("provider")}},
			{name: "git", dirs: []contribDir{{files: map[string]string{"x.rego": "package app.x\np := 1"}}}},
			{name: "provider", dirs: []contribDir{{contrib: &builder.Contribution{Roots: []string{"lazy"}}}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		checkRoots(t, b, "app/x", "lazy")
	})

	t.Run("mounted with prefix", func(t *testing.T) {
		b, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{mnt("provider", "", "data.mounted")}},
			{name: "provider", dirs: []contribDir{{
				files:   map[string]string{"p.rego": "package lib.p\nq := 1"},
				contrib: &builder.Contribution{Roots: []string{"lib/p", "lib/lazy"}},
			}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		checkRoots(t, b, "mounted/lib/p", "mounted/lib/lazy")
	})

	t.Run("outside mount path is dropped", func(t *testing.T) {
		b, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{mnt("provider", "data.lib", "data.mounted")}},
			{name: "provider", dirs: []contribDir{{
				files:   map[string]string{"p.rego": "package lib.p\nq := 1"},
				contrib: &builder.Contribution{Roots: []string{"lib/lazy", "other/lazy"}},
			}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		checkRoots(t, b, "mounted/p", "mounted/lazy")
	})

	t.Run("overlap with another source", func(t *testing.T) {
		_, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{req("git"), req("provider")}},
			{name: "git", dirs: []contribDir{{files: map[string]string{"x.rego": "package authz.main.extra\np := 1"}}}},
			{name: "provider", dirs: []contribDir{{contrib: &builder.Contribution{Roots: []string{"authz/main"}}}}},
		})
		var conflict *builder.PackageConflictErr
		if !errors.As(err, &conflict) {
			t.Fatalf("expected PackageConflictErr, got %v", err)
		}
	})

	t.Run("survives source manifest roots", func(t *testing.T) {
		b, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{req("git"), req("provider")}},
			{name: "git", dirs: []contribDir{{files: map[string]string{
				"x.rego":    "package app.x\np := 1",
				".manifest": `{"roots": ["app"]}`,
			}}}},
			{name: "provider", dirs: []contribDir{{contrib: &builder.Contribution{Roots: []string{"lazy"}}}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		checkRoots(t, b, "app", "lazy")
	})

	t.Run("covered by source manifest root", func(t *testing.T) {
		b, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{req("git"), req("provider")}},
			{name: "git", dirs: []contribDir{{files: map[string]string{
				"x.rego":    "package app.x\np := 1",
				".manifest": `{"roots": ["app", "shared"]}`,
			}}}},
			{name: "provider", dirs: []contribDir{{contrib: &builder.Contribution{Roots: []string{"shared/lazy"}}}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		checkRoots(t, b, "app", "shared")
	})

	t.Run("broader than source manifest root", func(t *testing.T) {
		_, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{req("git"), req("provider")}},
			{name: "git", dirs: []contribDir{{files: map[string]string{
				"x.rego":    "package app.x\np := 1",
				".manifest": `{"roots": ["app/x", "lib/y"]}`,
			}}}},
			{name: "provider", dirs: []contribDir{{contrib: &builder.Contribution{Roots: []string{"lib"}}}}},
		})
		exp := `source "provider" claims root "lib", which overlaps root "lib/y" from the .manifest of source "git"`
		if err == nil || err.Error() != exp {
			t.Fatalf("expected %q, got %v", exp, err)
		}
	})

	for _, claimed := range [][]string{{"lazy/users", "lazy"}, {"lazy", "lazy/users"}} {
		t.Run("nested claimed roots with source manifest roots "+strings.Join(claimed, ","), func(t *testing.T) {
			b, err := buildWithContributions(t, []contribSource{
				{name: "bundle", requirements: []config.Requirement{req("git"), req("provider")}},
				{name: "git", dirs: []contribDir{{files: map[string]string{
					"x.rego":    "package app.x\np := 1",
					".manifest": `{"roots": ["app"]}`,
				}}}},
				{name: "provider", dirs: []contribDir{{contrib: &builder.Contribution{Roots: claimed}}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			checkRoots(t, b, "app", "lazy")
		})
	}

	t.Run("nested claimed roots still checked against source manifest roots", func(t *testing.T) {
		_, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{req("git"), req("provider")}},
			{name: "git", dirs: []contribDir{{files: map[string]string{
				"x.rego":    "package app.x\np := 1",
				".manifest": `{"roots": ["app", "lazy/users/x"]}`,
			}}}},
			{name: "provider", dirs: []contribDir{{contrib: &builder.Contribution{Roots: []string{"lazy/users", "lazy"}}}}},
		})
		exp := `source "provider" claims root "lazy", which overlaps root "lazy/users/x" from the .manifest of source "git"`
		if err == nil || err.Error() != exp {
			t.Fatalf("expected %q, got %v", exp, err)
		}
	})

	t.Run("invalid root", func(t *testing.T) {
		_, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{req("provider")}},
			{name: "provider", dirs: []contribDir{{contrib: &builder.Contribution{Roots: []string{"a//b"}}}}},
		})
		if err == nil || !strings.Contains(err.Error(), `claimed root "a//b"`) {
			t.Fatalf("expected invalid root error, got %v", err)
		}
	})
}

func TestContributionMetadata(t *testing.T) {
	t.Run("merged into manifest", func(t *testing.T) {
		b, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{req("one"), req("two")}},
			{name: "one", dirs: []contribDir{{
				files:   map[string]string{"x.rego": "package one\np := 1"},
				contrib: &builder.Contribution{Metadata: map[string]any{"a": map[string]any{"k": "v"}}},
			}}},
			{name: "two", dirs: []contribDir{{
				files:   map[string]string{"x.rego": "package two\np := 1"},
				contrib: &builder.Contribution{Metadata: map[string]any{"b": []any{"x"}}},
			}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		exp := map[string]any{"a": map[string]any{"k": "v"}, "b": []any{"x"}}
		if diff := cmp.Diff(exp, b.Manifest.Metadata); diff != "" {
			t.Errorf("metadata (-want,+got):\n%s", diff)
		}
	})

	t.Run("same key from two sources", func(t *testing.T) {
		_, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{req("one"), req("two")}},
			{name: "one", dirs: []contribDir{{
				files:   map[string]string{"x.rego": "package one\np := 1"},
				contrib: &builder.Contribution{Metadata: map[string]any{"a": 1}},
			}}},
			{name: "two", dirs: []contribDir{{
				files:   map[string]string{"x.rego": "package two\np := 1"},
				contrib: &builder.Contribution{Metadata: map[string]any{"a": 2}},
			}}},
		})
		if err == nil || !strings.Contains(err.Error(), `manifest metadata key "a" contributed by both source "one" and source "two"`) {
			t.Fatalf("expected metadata conflict, got %v", err)
		}
	})

	t.Run("same source required twice", func(t *testing.T) {
		b, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{
				mnt("provider", "", "data.m1"),
				mnt("provider", "", "data.m2"),
			}},
			{name: "provider", dirs: []contribDir{{
				files:   map[string]string{"x.rego": "package p\nq := 1"},
				contrib: &builder.Contribution{Metadata: map[string]any{"a": "v"}},
			}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(map[string]any{"a": "v"}, b.Manifest.Metadata); diff != "" {
			t.Errorf("metadata (-want,+got):\n%s", diff)
		}
	})

	t.Run("none contributed", func(t *testing.T) {
		b, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{req("git")}},
			{name: "git", dirs: []contribDir{{files: map[string]string{
				"x.rego":    "package app.x\np := 1",
				".manifest": `{"metadata": {"ignored": true}}`,
			}}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if b.Manifest.Metadata != nil {
			t.Errorf("expected no metadata, got %v", b.Manifest.Metadata)
		}
	})
}

func TestContributionRegoVersion(t *testing.T) {
	v1Only := "package app.v1\nallow if input.x == 1\n"

	t.Run("v1 directory", func(t *testing.T) {
		b, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{req("provider")}},
			{name: "provider", dirs: []contribDir{{
				files:   map[string]string{"x.rego": v1Only},
				contrib: &builder.Contribution{RegoVersion: new(1)},
			}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := *b.Manifest.RegoVersion; got != 1 {
			t.Errorf("expected rego_version 1, got %d", got)
		}
	})

	t.Run("takes precedence over source manifest", func(t *testing.T) {
		b, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{req("provider")}},
			{name: "provider", dirs: []contribDir{{
				files:   map[string]string{"x.rego": v1Only, ".manifest": `{"rego_version": 0}`},
				contrib: &builder.Contribution{RegoVersion: new(1)},
			}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := *b.Manifest.RegoVersion; got != 1 {
			t.Errorf("expected rego_version 1, got %d", got)
		}
	})

	t.Run("does not leak to sibling directory", func(t *testing.T) {
		// Roots are found by parsing each directory with its own rego version:
		// the v0 sibling parses fine there (as v1 it would fail with a
		// "find roots" error). The bundle as a whole is then compiled as v1,
		// as with source manifests, so the v0 file fails at compile time.
		_, err := buildWithContributions(t, []contribSource{
			{name: "bundle", requirements: []config.Requirement{req("provider")}},
			{name: "provider", dirs: []contribDir{
				{
					files:   map[string]string{"x.rego": v1Only},
					contrib: &builder.Contribution{RegoVersion: new(1)},
				},
				{files: map[string]string{"y.rego": "package app.v0\np[x] { x := 1 }\n"}},
			}},
		})
		if err == nil || !strings.HasPrefix(err.Error(), "build:") {
			t.Fatalf("expected compile-time error, got %v", err)
		}
	})
}

func TestContributionCallback(t *testing.T) {
	newSources := func(t *testing.T, fn func() *builder.Contribution) []*builder.Source {
		t.Helper()
		name := "provider"
		root := builder.NewSource("bundle")
		root.Requirements = []config.Requirement{{Source: &name}}
		src := builder.NewSource(name)
		if err := src.AddDir(builder.Dir{Path: filepath.ToSlash(t.TempDir()), Contribution: fn}); err != nil {
			t.Fatal(err)
		}
		return []*builder.Source{root, src}
	}
	build := func(t *testing.T, srcs []*builder.Source) (*bundle.Bundle, error) {
		t.Helper()
		buf := bytes.NewBuffer(nil)
		if err := builder.New().WithSources(srcs).WithOutput(buf).Build(t.Context()); err != nil {
			return nil, err
		}
		b, err := bundle.NewReader(buf).Read()
		if err != nil {
			t.Fatal(err)
		}
		return &b, nil
	}

	t.Run("read at build time", func(t *testing.T) {
		// The worker updates the contribution after every sync, so the
		// builder must use the value current at Build, not at AddDir.
		var current *builder.Contribution
		srcs := newSources(t, func() *builder.Contribution { return current })

		current = &builder.Contribution{Roots: []string{"first"}}
		b, err := build(t, srcs)
		if err != nil {
			t.Fatal(err)
		}
		checkRoots(t, b, "first")

		current = &builder.Contribution{Roots: []string{"second"}}
		b, err = build(t, srcs)
		if err != nil {
			t.Fatal(err)
		}
		checkRoots(t, b, "second")
	})

	t.Run("called once per build", func(t *testing.T) {
		// The source is required twice (different mounts), so it is processed
		// twice. Each call returns a different value; if the builder called
		// the callback per pass, roots and metadata would mix both values.
		calls := 0
		name := "provider"
		root := builder.NewSource("bundle")
		root.Requirements = []config.Requirement{
			{Source: &name, Prefix: "data.m1"},
			{Source: &name, Prefix: "data.m2"},
		}
		src := builder.NewSource(name)
		if err := src.AddDir(builder.Dir{
			Path: filepath.ToSlash(t.TempDir()),
			Contribution: func() *builder.Contribution {
				calls++
				return &builder.Contribution{
					Roots:    []string{"call" + strconv.Itoa(calls)},
					Metadata: map[string]any{"call": strconv.Itoa(calls)},
				}
			},
		}); err != nil {
			t.Fatal(err)
		}

		b, err := build(t, []*builder.Source{root, src})
		if err != nil {
			t.Fatal(err)
		}
		if calls != 1 {
			t.Fatalf("expected 1 call, got %d", calls)
		}
		checkRoots(t, b, "m1/call1", "m2/call1")
		if diff := cmp.Diff(map[string]any{"call": "1"}, b.Manifest.Metadata); diff != "" {
			t.Errorf("metadata (-want,+got):\n%s", diff)
		}
	})

	t.Run("nil result", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "x.rego"), []byte("package app.x\np := 1"), 0o644); err != nil {
			t.Fatal(err)
		}
		name := "provider"
		root := builder.NewSource("bundle")
		root.Requirements = []config.Requirement{{Source: &name}}
		src := builder.NewSource(name)
		if err := src.AddDir(builder.Dir{
			Path:         filepath.ToSlash(dir),
			Contribution: func() *builder.Contribution { return nil },
		}); err != nil {
			t.Fatal(err)
		}
		b, err := build(t, []*builder.Source{root, src})
		if err != nil {
			t.Fatal(err)
		}
		checkRoots(t, b, "app/x")
		if b.Manifest.Metadata != nil {
			t.Errorf("expected no metadata, got %v", b.Manifest.Metadata)
		}
	})

	t.Run("unsupported rego version", func(t *testing.T) {
		srcs := newSources(t, func() *builder.Contribution {
			return &builder.Contribution{Roots: []string{"x"}, RegoVersion: new(2)}
		})
		_, err := build(t, srcs)
		if err == nil || !strings.Contains(err.Error(), `source "provider": unsupported rego version 2`) {
			t.Fatalf("expected unsupported rego version error, got %v", err)
		}
	})
}

// captureStderr runs fn and returns what it wrote to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestManifestRootsWarningIgnoresClaimedRoots(t *testing.T) {
	git := func(manifestRoots string) contribSource {
		return contribSource{name: "git", dirs: []contribDir{{files: map[string]string{
			"x.rego":    "package app.x\np := 1",
			".manifest": `{"roots": ` + manifestRoots + `}`,
		}}}}
	}

	t.Run("only claimed roots differ", func(t *testing.T) {
		out := captureStderr(t, func() {
			if _, err := buildWithContributions(t, []contribSource{
				{name: "bundle", requirements: []config.Requirement{req("git"), req("provider")}},
				git(`["app/x"]`),
				{name: "provider", dirs: []contribDir{{contrib: &builder.Contribution{Roots: []string{"lazy"}}}}},
			}); err != nil {
				t.Fatal(err)
			}
		})
		if out != "" {
			t.Errorf("expected no warning, got %q", out)
		}
	})

	t.Run("manifest differs from files", func(t *testing.T) {
		out := captureStderr(t, func() {
			if _, err := buildWithContributions(t, []contribSource{
				{name: "bundle", requirements: []config.Requirement{req("git"), req("provider")}},
				git(`["app"]`),
				{name: "provider", dirs: []contribDir{{contrib: &builder.Contribution{Roots: []string{"lazy"}}}}},
			}); err != nil {
				t.Fatal(err)
			}
		})
		exp := "builder: source manifest roots [app] differ from computed roots [app/x]; using manifest roots\n"
		if out != exp {
			t.Errorf("expected %q, got %q", exp, out)
		}
	})
}

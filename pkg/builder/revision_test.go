package builder_test

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	ocp_fs "github.com/open-policy-agent/opa-control-plane/internal/fs"
	"github.com/open-policy-agent/opa-control-plane/internal/gitsync"
	"github.com/open-policy-agent/opa-control-plane/pkg/builder"
)

func TestRevisionStableAcrossClones(t *testing.T) {
	upstream := newUpstreamRepo(t, map[string]string{
		"policy.rego": "package p\n\nallow := true\n",
		"data.json":   `{"team":"authz"}`,
	})

	// Two independent clones of the very same commit.
	a := cloneRepo(t, upstream, "clone-a")
	b := cloneRepo(t, upstream, "clone-b")

	if got, want := hashOf(t, filepath.Join(a, "policy.rego")), hashOf(t, filepath.Join(b, "policy.rego")); got != want {
		t.Fatalf("precondition failed: clones differ in tracked content")
	}

	revA := buildRevision(t, a, true)
	revB := buildRevision(t, b, true)

	if revA != revB {
		t.Errorf("revision differs across clones of identical content:\n clone-a = %s\n clone-b = %s", revA, revB)
	}

	// Without the exclusion the two clones must disagree
	rawA := buildRevision(t, a, false)
	rawB := buildRevision(t, b, false)

	if rawA == rawB {
		t.Errorf("unexpected same revision across clones %s", rawA)
	}
	if rawA == revA {
		t.Errorf("excluding VCS metadata did not change the hash (%s); the exclusion is not taking effect", revA)
	}
}

func TestVCSExclusionKeepsSourceContent(t *testing.T) {
	upstream := newUpstreamRepo(t, map[string]string{
		"policy.rego":               "package p\n\nallow := true\n",
		"data.json":                 `{"a":1}`,
		".gitignore":                "*.tmp\n",
		".github/workflows/ci.yaml": "name: ci\n",
		"lib/.gitkeep":              "",
	})
	clone := cloneRepo(t, upstream, "clone")

	got := hashedFiles(t, clone, true)

	want := map[string]bool{
		".github/workflows/ci.yaml": true,
		".gitignore":                true,
		"data.json":                 true,
		"lib/.gitkeep":              true,
		"policy.rego":               true,
	}

	for _, f := range got {
		if !want[f] {
			t.Errorf("unexpected file in hashed filesystem: %s", f)
		}
		delete(want, f)
	}
	for f := range want {
		t.Errorf("tracked file wrongly excluded from hashed filesystem: %s", f)
	}
}

func newUpstreamRepo(t *testing.T, files map[string]string) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "upstream")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		// Keep the committer deterministic and independent of the developer's config.
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_CONFIG_SYSTEM=/dev/null",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	git("init", "-b", "main")
	git("config", "user.email", "test@example.com")
	git("config", "user.name", "test")

	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	git("add", "-A")
	git("commit", "-m", "initial")

	return dir
}

func cloneRepo(t *testing.T, upstream, name string) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), name)
	ref := "main"
	if _, err := gitsync.New(dir, config.Git{Repo: upstream, Reference: &ref}, "test_src").Execute(context.Background()); err != nil {
		t.Fatalf("clone %s: %v", name, err)
	}
	return dir
}

func buildRevision(t *testing.T, dir string, excludeVCS bool) string {
	t.Helper()

	src := builder.NewSource("test_src")
	if err := src.AddDir(builder.Dir{Path: filepath.ToSlash(dir), ExcludeVCS: excludeVCS}); err != nil {
		t.Fatal(err)
	}

	var revision string
	err := builder.New().
		WithSources([]*builder.Source{src}).
		WithOutput(bytes.NewBuffer(nil)).
		WithRevisionFunc(func(fsys fs.FS) (string, error) {
			var err error
			revision, err = ocp_fs.HashFS(fsys)
			return revision, err
		}).
		Build(t.Context())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if revision == "" {
		t.Fatal("revision func was never invoked")
	}
	return revision
}

func hashedFiles(t *testing.T, dir string, excludeVCS bool) []string {
	t.Helper()

	src := builder.NewSource("test_src")
	if err := src.AddDir(builder.Dir{Path: filepath.ToSlash(dir), ExcludeVCS: excludeVCS}); err != nil {
		t.Fatal(err)
	}

	var files []string
	err := builder.New().
		WithSources([]*builder.Source{src}).
		WithOutput(bytes.NewBuffer(nil)).
		WithRevisionFunc(func(fsys fs.FS) (string, error) {
			return "x", fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				// Strip the "test_src/" mount prefix the builder applies.
				rel := p
				if i := len("test_src/"); len(p) > i && p[:i] == "test_src/" {
					rel = p[i:]
				}
				files = append(files, rel)
				return nil
			})
		}).
		Build(t.Context())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return files
}

func hashOf(t *testing.T, path string) string {
	t.Helper()

	bs, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(bs)
}

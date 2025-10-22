package mountfs_test

import (
	"io/fs"
	"testing"

	ocp_fs "github.com/open-policy-agent/opa-control-plane/internal/fs"
	"github.com/open-policy-agent/opa-control-plane/internal/fs/mountfs"
)

func TestMountFS(t *testing.T) {
	files0 := ocp_fs.MapFS(map[string]string{"a.rego": "package a"})
	files1 := ocp_fs.MapFS(map[string]string{"d.rego": "package d"})
	files2 := ocp_fs.MapFS(map[string]string{
		"b.rego": "package b",
		"c.rego": "package c",
	})
	fsys := mountfs.New(map[string]fs.FS{
		"foo/bar/baz":   files0,
		"foo/bar/baz/a": files1,
		"foo/baz":       files2,
	})
	t.Run("list root", func(t *testing.T) {
		xs, err := fs.ReadDir(fsys, ".")
		if err != nil {
			t.Fatal(err)
		}
		if exp, act := 1, len(xs); exp != act {
			t.Fatalf("expected %d entries, got %d", exp, act)
		}
		if exp, act := "foo", xs[0].Name(); exp != act {
			t.Fatalf("expected entry %s, got %s", exp, act)
		}
	})
	t.Run("list common prefix", func(t *testing.T) {
		xs, err := fs.ReadDir(fsys, "foo")
		if err != nil {
			t.Fatal(err)
		}
		if exp, act := 2, len(xs); exp != act {
			t.Fatalf("expected %d entries, got %d", exp, act)
		}
		if exp, act := "bar", xs[0].Name(); exp != act {
			t.Fatalf("expected entry %s, got %s", exp, act)
		}
		if exp, act := "baz", xs[1].Name(); exp != act {
			t.Fatalf("expected entry %s, got %s", exp, act)
		}
	})
	t.Run("list mount point", func(t *testing.T) {
		xs, err := fs.ReadDir(fsys, "foo/baz")
		if err != nil {
			t.Fatal(err)
		}
		if exp, act := 2, len(xs); exp != act {
			t.Fatalf("expected %d entries, got %d", exp, act)
		}
		if exp, act := "b.rego", xs[0].Name(); exp != act {
			t.Fatalf("expected entry %s, got %s", exp, act)
		}
		if exp, act := "c.rego", xs[1].Name(); exp != act {
			t.Fatalf("expected entry %s, got %s", exp, act)
		}
	})
	// NOTE(sr): The last two cases are just to capture all the peculiarities:
	// They have no relevance for our use of mountfs.
	t.Run("list mount point overlapping prefix", func(t *testing.T) {
		xs, err := fs.ReadDir(fsys, "foo/bar/baz")
		if err != nil {
			t.Fatal(err)
		}
		if exp, act := 1, len(xs); exp != act {
			t.Fatalf("expected %d entries, got %d", exp, act)
		}
		if exp, act := "a.rego", xs[0].Name(); exp != act {
			t.Fatalf("expected entry %s, got %s", exp, act)
		}
	})
	t.Run("list mount point with prefix mount ignored", func(t *testing.T) {
		xs, err := fs.ReadDir(fsys, "foo/bar/baz/a")
		if err != nil {
			t.Fatal(err)
		}
		if exp, act := 1, len(xs); exp != act {
			t.Fatalf("expected %d entries, got %d", exp, act)
		}
		if exp, act := "d.rego", xs[0].Name(); exp != act {
			t.Fatalf("expected entry %s, got %s", exp, act)
		}
	})
}

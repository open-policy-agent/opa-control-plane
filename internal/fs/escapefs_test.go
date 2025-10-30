package fs_test

import (
	"embed"
	"io/fs"
	"testing"

	ocp_fs "github.com/open-policy-agent/opa-control-plane/internal/fs"
)

//go:embed *
var data embed.FS

func TestEscapeFS(t *testing.T) {
	efs := ocp_fs.NewEscapeFS(data)
	f, _ := efs.Open("testdata/test:dir/test:0.txt")
	var content = make([]byte, 32)
	n, _ := f.Read(content)
	if string(content[0:n]) != "test" {
		t.Fatalf("expected 'test', got '%s'", string(content))
	}

	f, _ = efs.Open("testdata/test:dir/test#1.txt")
	n, _ = f.Read(content)
	if string(content[0:n]) != "test too" {
		t.Fatalf("expected 'test too', got '%s'", string(content))
	}

	files, _ := efs.ReadDir("testdata/test:dir")
	if len(files) != 2 || files[0].Name() != "test#1.txt" || files[1].Name() != "test:0.txt" {
		t.Fatalf("expected 2 files, got %d", len(files))
	}

	f, _ = efs.Open("testdata/test:dir")
	entries, _ := f.(fs.ReadDirFile).ReadDir(-1)
	if len(entries) != 2 {
		t.Fatalf("expected a directory of two entries, got %d", len(entries))
	}
}

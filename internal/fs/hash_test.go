package fs

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func TestHashDirectory(t *testing.T) {
	t.Run("empty directory", func(t *testing.T) {
		dir := t.TempDir()

		hash, err := HashDirectory(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hash == "" {
			t.Fatal("expected non-empty hash for empty directory")
		}
		// SHA-256 of empty input
		if hash != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
			t.Fatalf("unexpected hash for empty directory: %s", hash)
		}
	})

	t.Run("single file", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte(`{"key":"value"}`), 0644); err != nil {
			t.Fatal(err)
		}

		hash, err := HashDirectory(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hash == "" {
			t.Fatal("expected non-empty hash")
		}
		if len(hash) != 64 {
			t.Fatalf("expected 64-char hex hash, got %d chars: %s", len(hash), hash)
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		dir1 := t.TempDir()
		dir2 := t.TempDir()

		for _, dir := range []string{dir1, dir2} {
			if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"a":1}`), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "sub"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "sub", "b.json"), []byte(`{"b":2}`), 0644); err != nil {
				t.Fatal(err)
			}
		}

		hash1, err := HashDirectory(dir1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		hash2, err := HashDirectory(dir2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hash1 != hash2 {
			t.Fatalf("expected identical hashes for identical content, got %s and %s", hash1, hash2)
		}
	})

	t.Run("different content produces different hash", func(t *testing.T) {
		dir1 := t.TempDir()
		dir2 := t.TempDir()

		if err := os.WriteFile(filepath.Join(dir1, "data.json"), []byte(`{"a":1}`), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir2, "data.json"), []byte(`{"a":2}`), 0644); err != nil {
			t.Fatal(err)
		}

		hash1, err := HashDirectory(dir1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		hash2, err := HashDirectory(dir2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hash1 == hash2 {
			t.Fatal("expected different hashes for different content")
		}
	})

	t.Run("different filenames produce different hash", func(t *testing.T) {
		dir1 := t.TempDir()
		dir2 := t.TempDir()

		if err := os.WriteFile(filepath.Join(dir1, "a.json"), []byte(`same`), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir2, "b.json"), []byte(`same`), 0644); err != nil {
			t.Fatal(err)
		}

		hash1, err := HashDirectory(dir1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		hash2, err := HashDirectory(dir2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hash1 == hash2 {
			t.Fatal("expected different hashes for different filenames")
		}
	})
}

func TestHashFS(t *testing.T) {
	t.Run("empty fs", func(t *testing.T) {
		fsys := fstest.MapFS{}

		hash, err := HashFS(fsys)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hash != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
			t.Fatalf("unexpected hash for empty fs: %s", hash)
		}
	})

	t.Run("single file", func(t *testing.T) {
		fsys := fstest.MapFS{
			"data.json": &fstest.MapFile{Data: []byte(`{"key":"value"}`)},
		}

		hash, err := HashFS(fsys)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(hash) != 64 {
			t.Fatalf("expected 64-char hex hash, got %d chars: %s", len(hash), hash)
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		fs1 := fstest.MapFS{
			"a.json":     &fstest.MapFile{Data: []byte(`{"a":1}`)},
			"sub/b.json": &fstest.MapFile{Data: []byte(`{"b":2}`)},
		}
		fs2 := fstest.MapFS{
			"a.json":     &fstest.MapFile{Data: []byte(`{"a":1}`)},
			"sub/b.json": &fstest.MapFile{Data: []byte(`{"b":2}`)},
		}

		hash1, err := HashFS(fs1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		hash2, err := HashFS(fs2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hash1 != hash2 {
			t.Fatalf("expected identical hashes, got %s and %s", hash1, hash2)
		}
	})

	t.Run("matches HashDirectory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte(`{"key":"value"}`), 0644); err != nil {
			t.Fatal(err)
		}

		dirHash, err := HashDirectory(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		fsys := fstest.MapFS{
			"data.json": &fstest.MapFile{Data: []byte(`{"key":"value"}`)},
		}
		fsHash, err := HashFS(fsys)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if dirHash != fsHash {
			t.Fatalf("HashDirectory and HashFS produced different hashes: %s vs %s", dirHash, fsHash)
		}
	})

	t.Run("different content produces different hash", func(t *testing.T) {
		fs1 := fstest.MapFS{
			"data.json": &fstest.MapFile{Data: []byte(`{"a":1}`)},
		}
		fs2 := fstest.MapFS{
			"data.json": &fstest.MapFile{Data: []byte(`{"a":2}`)},
		}

		hash1, err := HashFS(fs1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		hash2, err := HashFS(fs2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hash1 == hash2 {
			t.Fatal("expected different hashes for different content")
		}
	})

	t.Run("different filenames produce different hash", func(t *testing.T) {
		fs1 := fstest.MapFS{
			"a.json": &fstest.MapFile{Data: []byte(`same`)},
		}
		fs2 := fstest.MapFS{
			"b.json": &fstest.MapFile{Data: []byte(`same`)},
		}

		hash1, err := HashFS(fs1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		hash2, err := HashFS(fs2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hash1 == hash2 {
			t.Fatal("expected different hashes for different filenames")
		}
	})
}

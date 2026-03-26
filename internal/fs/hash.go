package fs

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"sort"
)

// HashDirectory computes a deterministic SHA-256 hash over all files in a directory tree.
// Files are sorted by their relative path, and each file contributes its relative path
// (null-terminated) followed by its contents to the hash. An empty directory produces
// the hash of an empty input.
func HashDirectory(root string) (string, error) {
	return HashFS(os.DirFS(root))
}

// HashFS computes a deterministic SHA-256 hash over all files in an fs.FS.
// Files are sorted by path, each contributing its path (null-terminated)
// followed by its contents.
func HashFS(fsys fs.FS) (string, error) {
	var files []string

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	sort.Strings(files)

	h := sha256.New()
	for _, file := range files {
		h.Write([]byte(file))
		h.Write([]byte{0})

		f, err := fsys.Open(file)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			return "", err
		}
		f.Close()
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

package fs

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// HashDirectory computes a deterministic SHA-256 hash over all files in a directory tree.
// Files are sorted by their relative path, and each file contributes its relative path
// (null-terminated) followed by its contents to the hash. An empty directory produces
// the hash of an empty input.
func HashDirectory(root string) (string, error) {
	var files []string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			relPath, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files = append(files, relPath)
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

		fullPath := filepath.Join(root, file)
		f, err := os.Open(fullPath)
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

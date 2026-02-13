package sqlsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"iter"
	"os"
	"path/filepath"
	"sort"

	"github.com/open-policy-agent/opa-control-plane/internal/database"
)

// SQLDataSynchronizer is a struct that implements the Synchronizer interface for bundle files stored in SQL database.
// It is expected that the caller will handle concurrency and parallelism. The Synchronizer is not thread-safe. It
// dumps files stored in SQL database into a directory used by the builder package to construct a bundle.
type SQLDataSynchronizer struct {
	path  string
	query func(context.Context) iter.Seq2[database.Data, error]
	id    string
}

func NewSQLSourceDataSynchronizer(path string, db *database.Database, sourceID int64, sourceName string) *SQLDataSynchronizer {
	return &SQLDataSynchronizer{path: path, query: db.QuerySourceData(sourceID, sourceName), id: sourceName}
}

func (s *SQLDataSynchronizer) Execute(ctx context.Context) (map[string]any, error) {
	err := os.MkdirAll(s.path, 0755)
	if err != nil {
		return nil, err
	}

	for data, err := range s.query(ctx) {
		if err != nil {
			return nil, err
		}
		path := filepath.Join(s.path, data.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return nil, err
		}

		if err := os.WriteFile(path, data.Data, 0644); err != nil {
			return nil, err
		}
	}

	hashsum, err := computeDirectoryHash(s.path)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"hashsum": hashsum,
	}, nil
}

func computeDirectoryHash(root string) (string, error) {
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

	// Return hash even for empty directories
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (*SQLDataSynchronizer) Close(context.Context) {} // No resources to close.

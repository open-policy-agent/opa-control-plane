package sqlsync

import (
	"context"
	"iter"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa-control-plane/internal/database"
)

// SQLDataSynchronizer is a struct that implements the Synchronizer interface for bundle files stored in SQL database.
// It is expected that the caller will handle concurrency and parallelism. The Synchronizer is not thread-safe. It
// dumps files stored in SQL database into a directory used by the builder package to construct a bundle.
type SQLDataSynchronizer struct {
	path       string
	query      func(context.Context) iter.Seq2[database.Data, error]
	id         string
	sourceName string
}

func NewSQLSourceDataSynchronizer(path string, db *database.Database, sourceID int64, sourceName string) *SQLDataSynchronizer {
	return &SQLDataSynchronizer{path: path, query: db.QuerySourceData(sourceID, sourceName), id: sourceName, sourceName: sourceName}
}

func (s *SQLDataSynchronizer) SourceName() string {
	return s.sourceName
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

	return nil, nil
}

func (*SQLDataSynchronizer) Close(context.Context) {} // No resources to close.

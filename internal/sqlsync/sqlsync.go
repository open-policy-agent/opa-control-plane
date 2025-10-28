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
	path  string
	query func(context.Context) iter.Seq2[database.Data, error]
	id    string
}

func NewSQLSourceDataSynchronizer(path string, db *database.Database, id string) *SQLDataSynchronizer {
	return &SQLDataSynchronizer{path: path, query: db.QuerySourceData(id), id: id}
}

func (s *SQLDataSynchronizer) Execute(ctx context.Context) error {
	err := os.MkdirAll(s.path, 0755)
	if err != nil {
		return err
	}

	for data, err := range s.query(ctx) {
		if err != nil {
			return err
		}
		path := filepath.Join(s.path, data.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		if err := os.WriteFile(path, data.Data, 0644); err != nil {
			return err
		}
	}

	return nil
}

func (*SQLDataSynchronizer) Close(context.Context) {} // No resources to close.

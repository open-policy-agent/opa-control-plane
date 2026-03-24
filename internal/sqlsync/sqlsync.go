package sqlsync

import (
	"context"
	"iter"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa-control-plane/internal/database"
	internalfs "github.com/open-policy-agent/opa-control-plane/internal/fs"
)

// SQLDataSynchronizer is a struct that implements the Synchronizer interface for bundle files stored in SQL database.
// It is expected that the caller will handle concurrency and parallelism. The Synchronizer is not thread-safe. It
// dumps files stored in SQL database into a directory used by the builder package to construct a bundle.
type SQLDataSynchronizer struct {
	path           string
	query          func(context.Context) iter.Seq2[database.Data, error]
	id             string
	metadataFields []string // Fields to compute (e.g., ["hashsum"])
}

type SQLSyncOption func(*SQLDataSynchronizer)

// WithMetadataFields configures which metadata fields should be computed.
// If not specified or empty, no expensive metadata (like hashsum) will be computed.
func WithMetadataFields(fields []string) SQLSyncOption {
	return func(s *SQLDataSynchronizer) {
		s.metadataFields = fields
	}
}

func NewSQLSourceDataSynchronizer(path string, db *database.Database, sourceID int64, sourceName string, opts ...SQLSyncOption) *SQLDataSynchronizer {
	s := &SQLDataSynchronizer{
		path:  path,
		query: db.QuerySourceData(sourceID, sourceName),
		id:    sourceName,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
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

	metadata := make(map[string]any)

	// Only compute hash if explicitly requested via WithMetadataFields
	for _, field := range s.metadataFields {
		if field == "hash" {
			hash, err := internalfs.HashDirectory(s.path)
			if err != nil {
				return nil, err
			}
			metadata["hash"] = hash
			break
		}
	}

	// Return nil if no metadata was computed
	if len(metadata) == 0 {
		return nil, nil
	}

	return metadata, nil
}

func (*SQLDataSynchronizer) Close(context.Context) {} // No resources to close.

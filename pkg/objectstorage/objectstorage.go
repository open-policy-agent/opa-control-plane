package objectstore

import (
	"context"
	"io"
)

// ObjectStorage defines the interface for uploading and downloading bundle artifacts
// to/from object storage systems (e.g., S3, GCS, Azure Blob Storage).
type ObjectStorage interface {
	// Upload stores a bundle artifact in object storage.
	Upload(ctx context.Context, body io.ReadSeeker, name string, revision string, totalSize int64) error

	// Download retrieves a bundle artifact from object storage.
	Download(ctx context.Context) (io.Reader, error)
}

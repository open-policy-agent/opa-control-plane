package objectstore

import (
	"context"
	"io"
)

// ObjectStorage defines the interface for uploading bundle artifacts
// to object storage systems (e.g., S3, GCS, Azure Blob Storage).
type ObjectStorage interface {
	// Upload stores a bundle artifact in object storage.
	Upload(ctx context.Context, body io.ReadSeeker, name string, revision string, totalSize int64) error
}

// Downloader is an optional interface for retrieving bundle artifacts from object storage.
type Downloader interface {
	Download(ctx context.Context) (io.Reader, error)
}

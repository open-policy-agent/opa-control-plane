package objectstore

import (
	"context"
	"errors"
	"io"
)

// ErrNotModified is returned by Upload when the content already matches what
// is stored and no upload was performed.
var ErrNotModified = errors.New("object not modified")

// UploadOptions holds parameters for an Upload call.
type UploadOptions struct {
	Tenant    string
	Name      string
	Revision  string
	TotalSize int64
}

// ObjectStorage defines the interface for uploading and downloading bundle artifacts
// to/from object storage systems (e.g., S3, GCS, Azure Blob Storage).
type ObjectStorage interface {
	// Upload stores a bundle artifact in object storage.
	// Implementations may return ErrNotModified to indicate that the upload
	// was skipped because the content has not changed.
	Upload(ctx context.Context, body io.ReadSeeker, opts UploadOptions) error

	// Download retrieves a bundle artifact from object storage.
	Download(ctx context.Context) (io.Reader, error)
}

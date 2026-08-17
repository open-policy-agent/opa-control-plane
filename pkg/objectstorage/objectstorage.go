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

// VersionedObjectStorage is an optional capability an ObjectStorage
// implementation may provide. Callers can check for it via a type assertion;
// implementations that can't answer this cheaply (without building the
// bundle first) should simply not implement it.
type VersionedObjectStorage interface {
	// LatestRevision returns the revision recorded for the most recently
	// stored bundle matching opts.Tenant/opts.Name, without requiring the
	// caller to build the bundle first. It returns "" if no such bundle
	// exists yet, or the backend can't determine its revision cheaply.
	LatestRevision(ctx context.Context, opts UploadOptions) (string, error)
}

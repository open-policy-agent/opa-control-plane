package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fsouza/fake-gcs-server/fakestorage"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	ext_os "github.com/open-policy-agent/opa-control-plane/pkg/objectstorage"
)

// inProcessHTTPClient dispatches requests directly to an in-memory
// http.Handler instead of a real network connection, so tests using it don't
// need to bind a TCP listener.
type inProcessHTTPClient struct{ handler http.Handler }

func (c inProcessHTTPClient) Do(req *http.Request) (*http.Response, error) {
	// httptest.NewRecorder doesn't serialize req.ContentLength onto the wire
	// the way a real transport would, so gofakes3's MissingContentLength
	// check needs it set explicitly here.
	if req.ContentLength > 0 {
		req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
	}
	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

func TestS3(t *testing.T) {
	// Set mock AWS credentials to avoid IMDS errors.
	t.Setenv("AWS_ACCESS_KEY_ID", "mock-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "mock-secret-key")
	t.Setenv("AWS_REGION", "us-east-1")

	// Create a mock S3 service with a test bucket.

	mock := s3mem.New()
	if err := mock.CreateBucket("test"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(gofakes3.New(mock).Server())
	defer ts.Close()

	ctx := context.Background()

	// Upload a bundle to the mock S3 service.

	cfg := config.ObjectStorage{
		AmazonS3: &config.AmazonS3{
			Bucket: "test",
			Key:    "a/b/c",
			URL:    ts.URL,
		},
	}

	storage, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	bundle := bytes.NewReader([]byte("bundle content"))
	err = storage.Upload(ctx, bundle, ext_os.UploadOptions{})
	if err != nil {
		t.Fatalf("expected no error while uploading bundle: %v", err)
	}

	// Verify that the bundle was uploaded correctly.

	object, err := mock.GetObject("test", "a/b/c", nil)
	if err != nil {
		t.Fatalf("expected no error while getting object: %v", err)
	}

	contents, err := io.ReadAll(object.Contents)
	if err != nil {
		t.Fatalf("expected no error while reading object contents: %v", err)
	}

	if string(contents) != "bundle content" {
		t.Fatalf("expected object contents to be 'bundle content', got '%s'", contents)
	}

	reader, err := storage.Download(ctx)
	if err != nil {
		t.Fatal(err)
	}

	bs, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}

	if string(bs) != "bundle content" {
		t.Fatalf("expected object contents to be 'bundle content', got '%s'", contents)
	}
}

func TestS3WithRevision(t *testing.T) {
	// Set mock AWS credentials to avoid IMDS errors.
	t.Setenv("AWS_ACCESS_KEY_ID", "mock-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "mock-secret-key")
	t.Setenv("AWS_REGION", "us-east-1")

	// Create a mock S3 service with a test bucket.
	mock := s3mem.New()
	if err := mock.CreateBucket("test"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(gofakes3.New(mock).Server())
	defer ts.Close()

	ctx := context.Background()

	cfg := config.ObjectStorage{
		AmazonS3: &config.AmazonS3{
			Bucket: "test",
			Key:    "bundle-with-revision",
			URL:    ts.URL,
		},
	}

	storage, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	s3Storage, ok := storage.(*AmazonS3)
	if !ok {
		t.Fatal("expected storage to be of type *AmazonS3")
	}

	// Upload a bundle with a revision
	bundleContent := []byte("bundle content with revision")
	bundle := bytes.NewReader(bundleContent)
	revision := "v1.2.3"
	err = storage.Upload(ctx, bundle, ext_os.UploadOptions{Revision: revision})
	if err != nil {
		t.Fatalf("expected no error while uploading bundle: %v", err)
	}

	// Verify that the bundle was uploaded with correct metadata using HeadObject
	output, err := s3Storage.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &s3Storage.bucket,
		Key:    &s3Storage.key,
	})
	if err != nil {
		t.Fatalf("expected no error while getting object metadata: %v", err)
	}

	// Verify sha256 metadata is present
	expectedHash := sha256.Sum256(bundleContent)
	expectedHashStr := hex.EncodeToString(expectedHash[:])
	if output.Metadata["sha256"] != expectedHashStr {
		t.Errorf("expected sha256 metadata to be %q, got %q", expectedHashStr, output.Metadata["sha256"])
	}

	// Verify revision metadata is present
	if output.Metadata["revision"] != revision {
		t.Errorf("expected revision metadata to be %q, got %q", revision, output.Metadata["revision"])
	}
}

func TestS3WithoutRevision(t *testing.T) {
	// Set mock AWS credentials to avoid IMDS errors.
	t.Setenv("AWS_ACCESS_KEY_ID", "mock-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "mock-secret-key")
	t.Setenv("AWS_REGION", "us-east-1")

	// Create a mock S3 service with a test bucket.
	mock := s3mem.New()
	if err := mock.CreateBucket("test"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(gofakes3.New(mock).Server())
	defer ts.Close()

	ctx := context.Background()

	cfg := config.ObjectStorage{
		AmazonS3: &config.AmazonS3{
			Bucket: "test",
			Key:    "bundle-without-revision",
			URL:    ts.URL,
		},
	}

	storage, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	s3Storage, ok := storage.(*AmazonS3)
	if !ok {
		t.Fatal("expected storage to be of type *AmazonS3")
	}

	// Upload a bundle without a revision
	bundleContent := []byte("bundle content without revision")
	bundle := bytes.NewReader(bundleContent)
	err = storage.Upload(ctx, bundle, ext_os.UploadOptions{})
	if err != nil {
		t.Fatalf("expected no error while uploading bundle: %v", err)
	}

	// Verify that the bundle was uploaded with correct metadata using HeadObject
	output, err := s3Storage.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &s3Storage.bucket,
		Key:    &s3Storage.key,
	})
	if err != nil {
		t.Fatalf("expected no error while getting object metadata: %v", err)
	}

	// Verify sha256 metadata is present
	expectedHash := sha256.Sum256(bundleContent)
	expectedHashStr := hex.EncodeToString(expectedHash[:])
	if output.Metadata["sha256"] != expectedHashStr {
		t.Errorf("expected sha256 metadata to be %q, got %q", expectedHashStr, output.Metadata["sha256"])
	}

	// Verify revision metadata is NOT present when revision is empty
	if _, exists := output.Metadata["revision"]; exists {
		t.Errorf("expected revision metadata to not be present, but got %q", output.Metadata["revision"])
	}
}

func TestS3NotModified(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "mock-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "mock-secret-key")
	t.Setenv("AWS_REGION", "us-east-1")

	mock := s3mem.New()
	if err := mock.CreateBucket("test"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(gofakes3.New(mock).Server())
	defer ts.Close()

	ctx := context.Background()

	storage, err := New(ctx, config.ObjectStorage{
		AmazonS3: &config.AmazonS3{
			Bucket: "test",
			Key:    "not-modified",
			URL:    ts.URL,
		},
	})
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	content := []byte("same content")

	// First upload should succeed.
	r := bytes.NewReader(content)
	if err := storage.Upload(ctx, r, ext_os.UploadOptions{}); err != nil {
		t.Fatalf("first upload: %v", err)
	}

	// Second upload with identical content should return ErrNotModified.
	r = bytes.NewReader(content)
	if err := storage.Upload(ctx, r, ext_os.UploadOptions{}); !errors.Is(err, ext_os.ErrNotModified) {
		t.Fatalf("second upload: got %v, want ErrNotModified", err)
	}

	// Upload with different content should succeed.
	r2 := bytes.NewReader([]byte("different content"))
	if err := storage.Upload(ctx, r2, ext_os.UploadOptions{}); err != nil {
		t.Fatalf("third upload: %v", err)
	}
}

func TestS3LatestRevision(t *testing.T) {
	// Dispatches directly to gofakes3's handler in-process, so this test
	// doesn't need to bind a real TCP listener.
	mock := s3mem.New()
	if err := mock.CreateBucket("test"); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	client := s3.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("mock-access-key", "mock-secret-key", ""),
		HTTPClient:  inProcessHTTPClient{handler: gofakes3.New(mock).Server()},
	}, func(o *s3.Options) {
		o.UsePathStyle = true
		o.BaseEndpoint = aws.String("http://s3.local")
	})

	s3Storage := &AmazonS3{bucket: "test", key: "latest-revision", client: client}
	var storage ext_os.ObjectStorage = s3Storage

	// No object uploaded yet: LatestRevision should report "" rather than error.
	rev, err := s3Storage.LatestRevision(ctx, ext_os.UploadOptions{})
	if err != nil {
		t.Fatalf("expected no error for missing object, got %v", err)
	}
	if rev != "" {
		t.Fatalf("expected empty revision for missing object, got %q", rev)
	}

	// Upload without a revision: LatestRevision should still report "".
	if err := storage.Upload(ctx, bytes.NewReader([]byte("v1")), ext_os.UploadOptions{}); err != nil {
		t.Fatalf("upload without revision: %v", err)
	}
	rev, err = s3Storage.LatestRevision(ctx, ext_os.UploadOptions{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if rev != "" {
		t.Fatalf("expected empty revision when none was recorded, got %q", rev)
	}

	// Upload with a revision: LatestRevision should report it back.
	if err := storage.Upload(ctx, bytes.NewReader([]byte("v2")), ext_os.UploadOptions{Revision: "rev-abc"}); err != nil {
		t.Fatalf("upload with revision: %v", err)
	}
	rev, err = s3Storage.LatestRevision(ctx, ext_os.UploadOptions{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if rev != "rev-abc" {
		t.Fatalf("expected revision %q, got %q", "rev-abc", rev)
	}
}

func TestFileSystemNotModified(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")

	ctx := context.Background()

	storage, err := New(ctx, config.ObjectStorage{
		FileSystemStorage: &config.FileSystemStorage{Path: path},
	})
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	content := []byte("same content")

	// First upload should write the file.
	r := bytes.NewReader(content)
	if err := storage.Upload(ctx, r, ext_os.UploadOptions{}); err != nil {
		t.Fatalf("first upload: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("bundle file not created: %v", err)
	}

	// Second upload with identical content should return ErrNotModified.
	r = bytes.NewReader(content)
	if err := storage.Upload(ctx, r, ext_os.UploadOptions{}); !errors.Is(err, ext_os.ErrNotModified) {
		t.Fatalf("second upload: got %v, want ErrNotModified", err)
	}

	// Upload with different content should succeed.
	r2 := bytes.NewReader([]byte("different content"))
	if err := storage.Upload(ctx, r2, ext_os.UploadOptions{}); err != nil {
		t.Fatalf("third upload: %v", err)
	}
}

func TestGCSNotModified(t *testing.T) {
	mock := fakestorage.NewServer(nil)
	defer mock.Stop()

	mock.CreateBucketWithOpts(fakestorage.CreateBucketOpts{
		Name: "test",
	})

	// fake-gcs-server requires its own pre-configured client (using a custom
	// HTTP transport), we can't nicely pass this into the New constructor as we do with S3.
	gcsStorage := &GCPCloudStorage{
		bucket: "test",
		object: "not-modified",
		client: mock.Client(),
	}

	content := []byte("same content")

	// First upload should write the file.
	r := bytes.NewReader(content)
	if err := gcsStorage.Upload(t.Context(), r, ext_os.UploadOptions{}); err != nil {
		t.Fatalf("first upload: %v", err)
	}

	// Second upload with identical content should return ErrNotModified.
	r = bytes.NewReader(content)
	if err := gcsStorage.Upload(t.Context(), r, ext_os.UploadOptions{}); !errors.Is(err, ext_os.ErrNotModified) {
		t.Fatalf("second upload: got %v, want ErrNotModified", err)
	}

	// Upload with different content should succeed.
	r2 := bytes.NewReader([]byte("different content"))
	if err := gcsStorage.Upload(t.Context(), r2, ext_os.UploadOptions{}); err != nil {
		t.Fatalf("third upload: %v", err)
	}
}

func TestGCSLatestRevision(t *testing.T) {
	// NoListener avoids binding a real TCP port, since this test doesn't
	// otherwise depend on the network transport fake-gcs-server normally uses.
	mock, err := fakestorage.NewServerWithOptions(fakestorage.Options{NoListener: true})
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Stop()

	mock.CreateBucketWithOpts(fakestorage.CreateBucketOpts{
		Name: "test",
	})

	gcsStorage := &GCPCloudStorage{
		bucket: "test",
		object: "latest-revision",
		client: mock.Client(),
	}

	ctx := t.Context()

	// No object uploaded yet: LatestRevision should report "" rather than error.
	rev, err := gcsStorage.LatestRevision(ctx, ext_os.UploadOptions{})
	if err != nil {
		t.Fatalf("expected no error for missing object, got %v", err)
	}
	if rev != "" {
		t.Fatalf("expected empty revision for missing object, got %q", rev)
	}

	// Upload without a revision: LatestRevision should still report "".
	if err := gcsStorage.Upload(ctx, bytes.NewReader([]byte("v1")), ext_os.UploadOptions{}); err != nil {
		t.Fatalf("upload without revision: %v", err)
	}
	rev, err = gcsStorage.LatestRevision(ctx, ext_os.UploadOptions{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if rev != "" {
		t.Fatalf("expected empty revision when none was recorded, got %q", rev)
	}

	// Upload with a revision: LatestRevision should report it back.
	if err := gcsStorage.Upload(ctx, bytes.NewReader([]byte("v2")), ext_os.UploadOptions{Revision: "rev-xyz"}); err != nil {
		t.Fatalf("upload with revision: %v", err)
	}
	rev, err = gcsStorage.LatestRevision(ctx, ext_os.UploadOptions{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if rev != "rev-xyz" {
		t.Fatalf("expected revision %q, got %q", "rev-xyz", rev)
	}
}

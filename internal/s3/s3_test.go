package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/open-policy-agent/opa-control-plane/internal/config"
)

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
	err = storage.Upload(ctx, bundle, "testbundle", "", bundle.Size())
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
	err = storage.Upload(ctx, bundle, "testbundle", revision, bundle.Size())
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
	err = storage.Upload(ctx, bundle, "testbundle", "", bundle.Size())
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

func TestInMemoryStorage(t *testing.T) {
	ctx := context.Background()
	ms := NewInMemoryStorage()

	// Download before any upload should fail.
	if _, err := ms.Download(ctx); err == nil {
		t.Fatal("expected error on download before upload")
	}

	// Upload content.
	content := []byte("test bundle data")
	err := ms.Upload(ctx, bytes.NewReader(content), "mybundle", "rev1", int64(len(content)))
	if err != nil {
		t.Fatalf("unexpected upload error: %v", err)
	}

	// Download and verify.
	reader, err := ms.Download(ctx)
	if err != nil {
		t.Fatalf("unexpected download error: %v", err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("expected %q, got %q", content, got)
	}

	// Upload new content replaces old.
	content2 := []byte("updated bundle")
	if err := ms.Upload(ctx, bytes.NewReader(content2), "mybundle", "rev2", int64(len(content2))); err != nil {
		t.Fatalf("unexpected upload error: %v", err)
	}
	reader, _ = ms.Download(ctx)
	got, _ = io.ReadAll(reader)
	if !bytes.Equal(got, content2) {
		t.Fatalf("expected %q, got %q", content2, got)
	}
}

func TestInMemoryStorageServeHTTP(t *testing.T) {
	ctx := context.Background()
	ms := NewInMemoryStorage()

	// Serve before upload should return 404.
	req := httptest.NewRequest(http.MethodGet, "/bundles/test", nil)
	rec := httptest.NewRecorder()
	ms.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	// Upload content.
	content := []byte("gzipped bundle content")
	if err := ms.Upload(ctx, bytes.NewReader(content), "test", "rev1", int64(len(content))); err != nil {
		t.Fatal(err)
	}

	// Serve should return content with correct headers.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/bundles/test", nil)
	ms.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/gzip" {
		t.Fatalf("expected Content-Type application/gzip, got %q", ct)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected ETag header")
	}

	hash := sha256.Sum256(content)
	expectedETag := hex.EncodeToString(hash[:])
	if etag != expectedETag {
		t.Fatalf("expected ETag %q, got %q", expectedETag, etag)
	}
	if rev := rec.Header().Get("X-OPA-Revision"); rev != "rev1" {
		t.Fatalf("expected X-OPA-Revision rev1, got %q", rev)
	}
	if !bytes.Equal(rec.Body.Bytes(), content) {
		t.Fatal("body mismatch")
	}

	// If-None-Match with matching ETag should return 304.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/bundles/test", nil)
	req.Header.Set("If-None-Match", etag)
	ms.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", rec.Code)
	}

	// If-None-Match with non-matching ETag should return 200.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/bundles/test", nil)
	req.Header.Set("If-None-Match", "stale-etag")
	ms.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

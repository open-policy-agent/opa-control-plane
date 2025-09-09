package s3

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/styrainc/opa-control-plane/internal/config"
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
	err = storage.Upload(ctx, bundle)
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

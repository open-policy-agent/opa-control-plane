package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fsouza/fake-gcs-server/fakestorage"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	ext_os "github.com/open-policy-agent/opa-control-plane/pkg/objectstorage"
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

// azureBlobServer is a minimal in-memory stand-in for the Azure Blob Storage REST API. It implements just enough of
// Put Blob, Put Block, Put Block List and Get Blob Properties to exercise the upload path. Azurite would be more
// faithful, but it needs a container runtime that the rest of this package's tests do not depend on.
type azureBlobServer struct {
	t *testing.T

	mu       sync.Mutex
	content  map[string][]byte
	metadata map[string]map[string]string
	blocks   map[string][]byte

	// getPropertiesStatus and getPropertiesErrorCode, when set, make Get Blob Properties fail. Used to check that
	// errors other than a missing blob are not mistaken for an unchanged bundle.
	getPropertiesStatus    int
	getPropertiesErrorCode string

	puts int // number of blob writes that reached the server.
}

func newAzureBlobServer(t *testing.T) (*azureBlobServer, *httptest.Server) {
	t.Helper()

	s := &azureBlobServer{
		t:        t,
		content:  map[string][]byte{},
		metadata: map[string]map[string]string{},
		blocks:   map[string][]byte{},
	}

	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)

	return s, ts
}

// writes returns the number of blob writes the server has accepted.
func (s *azureBlobServer) writes() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.puts
}

func (s *azureBlobServer) blob(name string) ([]byte, map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.content[name], s.metadata[name]
}

// setBlobMetadata seeds metadata for a blob without going through an upload.
func (s *azureBlobServer) setBlobMetadata(name string, metadata map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.metadata[name] = metadata
}

// failGetProperties makes subsequent Get Blob Properties calls fail with the given status and Azure error code.
func (s *azureBlobServer) failGetProperties(status int, code string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.getPropertiesStatus = status
	s.getPropertiesErrorCode = code
}

func (s *azureBlobServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	blob := r.URL.Path
	comp := r.URL.Query().Get("comp")

	switch {
	case r.Method == http.MethodHead:
		// HEAD responses carry no body, so the error code travels in a header.
		if s.getPropertiesStatus != 0 {
			w.Header().Set("x-ms-error-code", s.getPropertiesErrorCode)
			w.WriteHeader(s.getPropertiesStatus)
			return
		}

		metadata, ok := s.metadata[blob]
		if !ok {
			w.Header().Set("x-ms-error-code", string(bloberror.BlobNotFound))
			w.WriteHeader(http.StatusNotFound)
			return
		}

		for k, v := range metadata {
			w.Header().Set("x-ms-meta-"+k, v)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(s.content[blob])))
		s.writeCommonHeaders(w)
		w.WriteHeader(http.StatusOK)

	case r.Method == http.MethodPut && comp == "block":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			s.t.Errorf("failed to read staged block: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		s.blocks[r.URL.Query().Get("blockid")] = body
		s.writeCommonHeaders(w)
		w.WriteHeader(http.StatusCreated)

	case r.Method == http.MethodPut && comp == "blocklist":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			s.t.Errorf("failed to read block list: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var list struct {
			Latest []string `xml:"Latest"`
		}
		if err := xml.Unmarshal(body, &list); err != nil {
			s.t.Errorf("failed to unmarshal block list: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var assembled []byte
		for _, id := range list.Latest {
			assembled = append(assembled, s.blocks[id]...)
		}

		s.content[blob] = assembled
		s.metadata[blob] = metadataFromHeader(r.Header)
		s.puts++
		s.writeCommonHeaders(w)
		w.WriteHeader(http.StatusCreated)

	case r.Method == http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			s.t.Errorf("failed to read blob: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		s.content[blob] = body
		s.metadata[blob] = metadataFromHeader(r.Header)
		s.puts++
		s.writeCommonHeaders(w)
		w.WriteHeader(http.StatusCreated)

	default:
		s.t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (*azureBlobServer) writeCommonHeaders(w http.ResponseWriter) {
	w.Header().Set("ETag", `"0x8DWHATEVER"`)
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
}

func metadataFromHeader(h http.Header) map[string]string {
	const prefix = "X-Ms-Meta-"

	metadata := map[string]string{}
	for k, v := range h {
		if after, ok := strings.CutPrefix(k, prefix); ok && len(v) > 0 {
			metadata[strings.ToLower(after)] = v[0]
		}
	}

	return metadata
}

// newAzureStorage wires an AzureBlobStorage to url through the New constructor. A shared key credential is used
// because the alternative, DefaultAzureCredential, probes the environment for real Azure credentials.
func newAzureStorage(t *testing.T, url, path string) ext_os.ObjectStorage {
	t.Helper()

	credentials := &config.SecretRef{Name: "azure"}
	credentials.SetResolver(func(context.Context) (any, error) {
		return config.SecretAzure{
			AccountName: "testaccount",
			AccountKey:  base64.StdEncoding.EncodeToString([]byte("test-account-key")),
		}, nil
	})

	storage, err := New(t.Context(), config.ObjectStorage{
		AzureBlobStorage: &config.AzureBlobStorage{
			AccountURL:  url,
			Container:   "test",
			Path:        path,
			Credentials: credentials,
		},
	})
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	return storage
}

// TestAzureNotModified also covers the metadata key casing hazard: net/http canonicalizes the response header names,
// so the SDK hands back the key as "Sha256" and a case-sensitive lookup for "sha256" would miss, making the second
// upload proceed and failing this test.
func TestAzureNotModified(t *testing.T) {
	server, ts := newAzureBlobServer(t)
	storage := newAzureStorage(t, ts.URL, "not-modified")

	content := []byte("same content")

	// First upload should succeed.
	r := bytes.NewReader(content)
	if err := storage.Upload(t.Context(), r, ext_os.UploadOptions{}); err != nil {
		t.Fatalf("first upload: %v", err)
	}

	// Second upload with identical content should return ErrNotModified.
	r = bytes.NewReader(content)
	if err := storage.Upload(t.Context(), r, ext_os.UploadOptions{}); !errors.Is(err, ext_os.ErrNotModified) {
		t.Fatalf("second upload: got %v, want ErrNotModified", err)
	}

	// Upload with different content should succeed.
	r2 := bytes.NewReader([]byte("different content"))
	if err := storage.Upload(t.Context(), r2, ext_os.UploadOptions{}); err != nil {
		t.Fatalf("third upload: %v", err)
	}

	// The skipped upload should not have reached the server: a new blob version is the cost this avoids.
	if got := server.writes(); got != 2 {
		t.Errorf("expected 2 blob writes, got %d", got)
	}

	if content, _ := server.blob("/test/not-modified"); string(content) != "different content" {
		t.Errorf("expected blob contents to be 'different content', got %q", content)
	}
}

// TestAzureNotModifiedMultipleBlocks covers bundles larger than the SDK's 1 MiB block size, which are uploaded as
// staged blocks committed by Put Block List rather than by a single Put Blob. Real bundles routinely exceed that, and
// the metadata this relies on travels on a different request in that case.
func TestAzureNotModifiedMultipleBlocks(t *testing.T) {
	server, ts := newAzureBlobServer(t)
	storage := newAzureStorage(t, ts.URL, "not-modified-blocks")

	// Just over two blocks at the default 1 MiB block size.
	content := bytes.Repeat([]byte("opa"), 750_000)

	if err := storage.Upload(t.Context(), bytes.NewReader(content), ext_os.UploadOptions{}); err != nil {
		t.Fatalf("first upload: %v", err)
	}

	stored, metadata := server.blob("/test/not-modified-blocks")
	if !bytes.Equal(stored, content) {
		t.Fatalf("expected %d bytes to be stored, got %d", len(content), len(stored))
	}

	digest := sha256.Sum256(content)
	if want := hex.EncodeToString(digest[:]); metadata["sha256"] != want {
		t.Errorf("expected sha256 metadata to be %q, got %q", want, metadata["sha256"])
	}

	if err := storage.Upload(t.Context(), bytes.NewReader(content), ext_os.UploadOptions{}); !errors.Is(err, ext_os.ErrNotModified) {
		t.Fatalf("second upload: got %v, want ErrNotModified", err)
	}

	if got := server.writes(); got != 1 {
		t.Errorf("expected 1 blob write, got %d", got)
	}
}

func TestAzureWithRevision(t *testing.T) {
	server, ts := newAzureBlobServer(t)
	storage := newAzureStorage(t, ts.URL, "bundle-with-revision")

	content := []byte("bundle content with revision")
	revision := "v1.2.3"

	if err := storage.Upload(t.Context(), bytes.NewReader(content), ext_os.UploadOptions{Revision: revision}); err != nil {
		t.Fatalf("expected no error while uploading bundle: %v", err)
	}

	_, metadata := server.blob("/test/bundle-with-revision")

	digest := sha256.Sum256(content)
	if want := hex.EncodeToString(digest[:]); metadata["sha256"] != want {
		t.Errorf("expected sha256 metadata to be %q, got %q", want, metadata["sha256"])
	}

	if metadata["revision"] != revision {
		t.Errorf("expected revision metadata to be %q, got %q", revision, metadata["revision"])
	}
}

func TestAzureWithoutRevision(t *testing.T) {
	server, ts := newAzureBlobServer(t)
	storage := newAzureStorage(t, ts.URL, "bundle-without-revision")

	content := []byte("bundle content without revision")

	if err := storage.Upload(t.Context(), bytes.NewReader(content), ext_os.UploadOptions{}); err != nil {
		t.Fatalf("expected no error while uploading bundle: %v", err)
	}

	_, metadata := server.blob("/test/bundle-without-revision")

	digest := sha256.Sum256(content)
	if want := hex.EncodeToString(digest[:]); metadata["sha256"] != want {
		t.Errorf("expected sha256 metadata to be %q, got %q", want, metadata["sha256"])
	}

	if _, ok := metadata["revision"]; ok {
		t.Errorf("expected no revision metadata, got %q", metadata["revision"])
	}
}

// TestAzureUploadsBlobWithoutDigest covers the upgrade path: blobs written by earlier releases carry at most a
// revision, so the first upload after upgrading has no digest to compare against and has to proceed.
func TestAzureUploadsBlobWithoutDigest(t *testing.T) {
	server, ts := newAzureBlobServer(t)
	server.setBlobMetadata("/test/no-digest", map[string]string{"revision": "v1.0.0"})

	storage := newAzureStorage(t, ts.URL, "no-digest")

	if err := storage.Upload(t.Context(), bytes.NewReader([]byte("bundle content")), ext_os.UploadOptions{}); err != nil {
		t.Fatalf("expected no error while uploading bundle: %v", err)
	}

	if got := server.writes(); got != 1 {
		t.Errorf("expected 1 blob write, got %d", got)
	}
}

// TestAzureGetPropertiesError checks that an error other than a missing blob is reported rather than being treated as
// either an unchanged or a changed bundle. Reading the properties needs its own permission, so a credential allowed to
// write but not read has to fail loudly instead of silently re-uploading every interval.
func TestAzureGetPropertiesError(t *testing.T) {
	server, ts := newAzureBlobServer(t)
	server.failGetProperties(http.StatusForbidden, "AuthorizationPermissionMismatch")

	storage := newAzureStorage(t, ts.URL, "forbidden")

	err := storage.Upload(t.Context(), bytes.NewReader([]byte("bundle content")), ext_os.UploadOptions{})
	if err == nil {
		t.Fatal("expected an error, got none")
	}
	if errors.Is(err, ext_os.ErrNotModified) {
		t.Fatal("expected a failure, got ErrNotModified")
	}

	if got := server.writes(); got != 0 {
		t.Errorf("expected no blob writes, got %d", got)
	}
}

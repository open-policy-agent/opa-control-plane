// s3 connects OPA Control Plane to S3-compatible object storages.
package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"cloud.google.com/go/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	internal_aws "github.com/styrainc/opa-control-plane/internal/aws"
	"github.com/styrainc/opa-control-plane/internal/config"
	"google.golang.org/api/option"
)

var (
	_ ObjectStorage = (*AmazonS3)(nil)
	_ ObjectStorage = (*GCPCloudStorage)(nil)
	_ ObjectStorage = (*AzureBlobStorage)(nil)
	_ ObjectStorage = (*FileSystemStorage)(nil)
)

type (
	ObjectStorage interface {
		Upload(ctx context.Context, body io.ReadSeeker) error
		Download(ctx context.Context) (io.Reader, error)
	}

	AmazonS3 struct {
		bucket   string
		key      string
		uploader *manager.Uploader
		client   *s3.Client
	}

	GCPCloudStorage struct {
		project string
		bucket  string
		object  string
		client  *storage.Client
	}

	AzureBlobStorage struct {
		container string
		path      string
		client    *azblob.Client
	}

	FileSystemStorage struct {
		path   string
		digest []byte // digest of the previously written bundle, to avoid rewriting the same content.
	}
)

// New creates a new S3 client based on the provided configuration.
func New(ctx context.Context, c config.ObjectStorage) (ObjectStorage, error) {
	switch {
	case c.AmazonS3 != nil:
		// There are two options for authentication to Amazon S3:
		//
		// 1. Using no secret at all. In this case, the AWS SDK will use the default credential provider chain to authenticate. It proceeds in
		//    the following in order:
		//    a) Environment variables.
		//    b) Shared credentials file.
		//    c) If your application uses an ECS task definition or RunTask API operation, IAM role for tasks.
		//    d) If your application is running on an Amazon EC2 instance, IAM role for Amazon EC2.
		// 2. Using a secret of type "aws_auth". The secret stores the AWS credentials to use to authenticate.

		awsCfg, err := internal_aws.Config(ctx, c.AmazonS3.Region, c.AmazonS3.Credentials)
		if err != nil {
			return nil, err
		}

		client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
			if c.AmazonS3.URL != "" {
				o.UsePathStyle = true
				o.BaseEndpoint = aws.String(c.AmazonS3.URL)
			}
		})

		return &AmazonS3{bucket: c.AmazonS3.Bucket, key: c.AmazonS3.Key, uploader: manager.NewUploader(client), client: client}, nil
	case c.GCPCloudStorage != nil:
		var client *storage.Client

		// There are two options for authentication to Google Cloud Storage:
		//
		// 1. Using no secret at all. In this case, the Google Cloud Storage SDK will use the default credential provider chain to authenticate. It proceeds in
		// the following in order:
		//    a) GOOGLE_APPLICATION_CREDENTIALS environment variable.
		//    b) A credential file created by using the gcloud auth application-default login command.
		//    c) The attached service account, returned by the metadata server.
		// 2. Using a secret of type "gcp_auth". The secret stores the API key or JSON credentials to use to authenticate.

		if c.GCPCloudStorage.Credentials == nil {
			// Option 1: default chain.
			var err error
			client, err = storage.NewClient(ctx)
			if err != nil {
				return nil, err
			}
		} else {
			// Option 2: use a secret of type "gcp_auth".
			value, err := c.GCPCloudStorage.Credentials.Resolve(ctx)
			if err != nil {
				return nil, err
			}

			auth, ok := value.(config.SecretGCP)
			if !ok {
				return nil, errors.New("invalid GCP secret type")
			}

			if auth.APIKey != "" {
				client, err = storage.NewClient(ctx, option.WithAPIKey(auth.APIKey))
				if err != nil {
					return nil, err
				}
			} else if auth.Credentials != "" {
				client, err = storage.NewClient(ctx, option.WithCredentialsJSON([]byte(auth.Credentials)))
				if err != nil {
					return nil, err
				}
			}
		}

		return &GCPCloudStorage{project: c.GCPCloudStorage.Project, bucket: c.GCPCloudStorage.Bucket, object: c.GCPCloudStorage.Object, client: client}, nil
	case c.AzureBlobStorage != nil:
		var client *azblob.Client

		// There are two options for authentication to Azure Blob Storage:
		//
		// 1) Use "DefaultAzureCredential" which is an opinionated, preconfigured chain of credentials. It's designed to support many environments,
		//    along with the most common authentication flows and developer tools:
		//
		//    a) Reads a collection of environment variables to determine if an application service principal (application user) is configured for the app.
		//       If so, DefaultAzureCredential uses these values to authenticate the app to Azure. This method is most often used in server environments
		//       but can also be used when developing locally.
		//    b) If the app is deployed to an Azure host with Workload Identity enabled, authenticate that account.
		//    c) If the app is deployed to an Azure host with Managed Identity enabled, authenticate the app to Azure using that Managed Identity.
		//    d) If the developer authenticated to Azure using Azure CLI's az login command, authenticate the app to Azure using that same account.
		//    e) If the developer authenticated to Azure using Azure Developer CLI's azd auth login command, authenticate with that account.
		// 2) Use the credentials (account name and account key) provided in the configuration.

		if c.AzureBlobStorage.Credentials == nil {
			// Option 1: Use "DefaultAzureCredential".
			credential, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				return nil, err
			}

			client, err = azblob.NewClient(c.AzureBlobStorage.AccountURL, credential, nil)
			if err != nil {
				return nil, err
			}
		} else {
			// Option 2: Use the credentials provided in the configuration.
			value, err := c.AzureBlobStorage.Credentials.Resolve(ctx)
			if err != nil {
				return nil, err
			}

			auth, ok := value.(config.SecretAzure)
			if !ok {
				return nil, errors.New("invalid Azure secret type")
			}

			credential, err := azblob.NewSharedKeyCredential(auth.AccountName, auth.AccountKey)
			if err != nil {
				return nil, err
			}

			client, err = azblob.NewClientWithSharedKeyCredential(c.AzureBlobStorage.AccountURL, credential, nil)
			if err != nil {
				return nil, err
			}
		}

		return &AzureBlobStorage{container: c.AzureBlobStorage.Container, path: c.AzureBlobStorage.Path, client: client}, nil
	case c.FileSystemStorage != nil:
		return &FileSystemStorage{path: c.FileSystemStorage.Path}, nil
	default:
		return nil, ErrUnsupportedProvider
	}
}

// ErrUnsupportedProvider is returned when an unsupported S3 provider is specified.
var ErrUnsupportedProvider = &Error{
	Message: "unsupported object storage provider",
}

type Error struct {
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

// Upload uploads a file to the S3-compatible storage. It computes the SHA256 digest of the file and records that to the object metadata.
// Relying on object ETag is not if the object is encrypted with SSE-C or SSE-KMS, as the ETag will not be the MD5 hash of the object.
// With (part) checksums, only parallellizable, less reliable checksums (CRCs) are supported.
func (s *AmazonS3) Upload(ctx context.Context, body io.ReadSeeker) error {

	digest, equal, err := s.check(ctx, body)
	if equal || err != nil {
		return err
	}

	_, err = body.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	_, err = s.uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key),
		Body:   body,
		Metadata: map[string]string{
			"sha256": hex.EncodeToString(digest),
		},
	})
	return err
}

func (s *AmazonS3) Download(ctx context.Context) (io.Reader, error) {

	output, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download object from S3: %w", err)
	}
	return output.Body, nil
}

func (s *AmazonS3) check(ctx context.Context, body io.Reader) ([]byte, bool, error) {
	d := sha256.New()
	_, err := io.Copy(d, body)
	if err != nil {
		return nil, false, err
	}

	digest := d.Sum(nil)

	output, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key),
	})
	if err != nil {
		var noKey *types.NoSuchKey
		var notFound *types.NotFound
		if errors.As(err, &noKey) || errors.As(err, &notFound) {
			return digest, false, nil
		}

		return nil, false, err
	}
	if output.Metadata == nil {
		return digest, false, nil
	}

	return digest, output.Metadata["sha256"] == hex.EncodeToString(digest), nil
}

func (s *GCPCloudStorage) Upload(ctx context.Context, body io.ReadSeeker) error {
	w := s.client.Bucket(s.bucket).Object(s.object).NewWriter(ctx)
	if _, err := io.Copy(w, body); err != nil {
		return err
	}

	return w.Close()
}

func (*GCPCloudStorage) Download(_ context.Context) (io.Reader, error) {
	return nil, errors.New("not implemented")
}

func (s *AzureBlobStorage) Upload(ctx context.Context, body io.ReadSeeker) error {
	_, err := s.client.UploadStream(ctx, s.container, s.path, body, nil)
	return err
}

func (*AzureBlobStorage) Download(_ context.Context) (io.Reader, error) {
	return nil, errors.New("not implemented")
}

func (s *FileSystemStorage) Upload(ctx context.Context, body io.ReadSeeker) error {
	digest, equal, err := s.check(ctx, body)
	if equal || err != nil {
		return err
	}

	_, err = body.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	file, err := os.Create(s.path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	if _, err := io.Copy(file, body); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	s.digest = digest // remember the digest of the last written file.

	return nil
}

func (s *FileSystemStorage) Download(ctx context.Context) (io.Reader, error) {
	file, err := os.Open(s.path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	return file, nil
}

func (s *FileSystemStorage) check(ctx context.Context, body io.Reader) ([]byte, bool, error) {
	d := sha256.New()
	_, err := io.Copy(d, body)
	if err != nil {
		return nil, false, err
	}

	digest := d.Sum(nil)

	return digest, bytes.Equal(digest, s.digest), nil
}

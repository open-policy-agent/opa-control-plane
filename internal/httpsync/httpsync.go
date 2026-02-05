package httpsync

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	internal_aws "github.com/open-policy-agent/opa-control-plane/internal/aws"
	"github.com/open-policy-agent/opa-control-plane/internal/config"
)

// HttpDataSynchronizer is a struct that implements the Synchronizer interface for downloading JSON from HTTP endpoints.
type HttpDataSynchronizer struct {
	path        string // The path where the data will be saved
	url         string
	method      string
	body        string
	headers     map[string]any // Headers to include in the HTTP request
	credentials *config.SecretRef
	region      string // AWS region for S3 datasources
	endpoint    string // Custom S3 endpoint for S3-compatible services
	client      *http.Client
	s3Client    *s3.Client
}

type HeaderSetter interface {
	SetHeader(*http.Request) error
}

func New(path, url, method, body string, headers map[string]any, credentials *config.SecretRef) *HttpDataSynchronizer {
	return &HttpDataSynchronizer{path: path, url: url, method: method, body: body, headers: headers, credentials: credentials}
}

func NewS3(path, url, region, endpoint string, credentials *config.SecretRef) *HttpDataSynchronizer {
	return &HttpDataSynchronizer{path: path, url: url, region: region, endpoint: endpoint, credentials: credentials}
}

func (s *HttpDataSynchronizer) Execute(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return err
	}

	f, err := os.Create(s.path)
	if err != nil {
		return err
	}
	defer f.Close()

	var body io.ReadCloser
	if s.region != "" { // S3 datasource - use AWS SDK
		body, err = s.executeS3(ctx)
	} else {
		body, err = s.executeHTTP(ctx)
	}
	if err != nil {
		_ = f.Truncate(0)
		return err
	}
	defer body.Close()

	_, err = io.Copy(f, body)
	if err != nil {
		_ = f.Truncate(0)
	}
	return err
}

func (s *HttpDataSynchronizer) executeHTTP(ctx context.Context) (io.ReadCloser, error) {
	if err := s.initClient(ctx); err != nil {
		return nil, fmt.Errorf("init client: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, s.method, s.url, strings.NewReader(s.body))
	if err != nil {
		return nil, err
	}

	s.setHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("unsuccessful status code %d", resp.StatusCode)
	}

	return resp.Body, nil
}

func (s *HttpDataSynchronizer) executeS3(ctx context.Context) (io.ReadCloser, error) {
	if err := s.initS3Client(ctx); err != nil {
		return nil, fmt.Errorf("init S3 client: %w", err)
	}

	bucket, key, err := parseS3URL(s.url)
	if err != nil {
		return nil, fmt.Errorf("parse S3 URL: %w", err)
	}

	result, err := s.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("S3 GetObject: %w", err)
	}

	return result.Body, nil
}

func (*HttpDataSynchronizer) Close(context.Context) {
	// No resources to close for HTTP synchronizer
}

func (s *HttpDataSynchronizer) initClient(ctx context.Context) error {
	if s.client != nil {
		return nil
	}

	if s.credentials == nil {
		s.client = http.DefaultClient
		return nil
	}

	secret, err := s.credentials.Resolve(ctx)
	if err != nil {
		return err
	}

	if secret, ok := secret.(config.ClientSecret); ok {
		s.client, err = secret.Client(ctx)
		return err
	}
	return fmt.Errorf("unsupported secret type for http sync: %T", secret)
}

func (s *HttpDataSynchronizer) initS3Client(ctx context.Context) error {
	if s.s3Client != nil {
		return nil
	}

	awsCfg, err := internal_aws.Config(ctx, s.region, s.credentials)
	if err != nil {
		return err
	}

	s.s3Client = s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if s.endpoint != "" {
			o.UsePathStyle = true
			o.BaseEndpoint = aws.String(s.endpoint)
		}
	})

	return nil
}

// parseS3URL extracts bucket and key from an S3 URL
// Supports both virtual-hosted style and path-style URLs
func parseS3URL(urlStr string) (bucket, key string, err error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", "", err
	}

	// Path-style: http://endpoint/bucket/key or https://s3.region.amazonaws.com/bucket/key
	if strings.HasPrefix(u.Host, "s3.") || strings.HasPrefix(u.Host, "s3-") || !strings.Contains(u.Host, ".s3.") {
		parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 2)
		if len(parts) < 2 {
			return "", "", fmt.Errorf("invalid S3 path-style URL: %s", urlStr)
		}
		return parts[0], parts[1], nil
	}

	// Virtual-hosted style: https://bucket.s3.region.amazonaws.com/key
	bucket = strings.Split(u.Host, ".")[0]
	key = strings.TrimPrefix(u.Path, "/")
	if key == "" {
		return "", "", fmt.Errorf("invalid S3 virtual-hosted URL: %s", urlStr)
	}

	return bucket, key, nil
}

func (s *HttpDataSynchronizer) setHeaders(req *http.Request) {
	for name, value := range s.headers {
		if value, ok := value.(string); ok && value != "" {
			req.Header.Set(name, value)
		}
	}
}

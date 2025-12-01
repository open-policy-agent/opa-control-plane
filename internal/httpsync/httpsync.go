package httpsync

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

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
	client      *http.Client
}

type HeaderSetter interface {
	SetHeader(*http.Request) error
}

func New(path string, url string, method string, body string, headers map[string]any, credentials *config.SecretRef) *HttpDataSynchronizer {
	return &HttpDataSynchronizer{path: path, url: url, method: method, body: body, headers: headers, credentials: credentials}
}

func (s *HttpDataSynchronizer) Execute(ctx context.Context) error {
	err := os.MkdirAll(filepath.Dir(s.path), 0755)
	if err != nil {
		return err
	}

	f, err := os.Create(s.path)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := s.initClient(ctx); err != nil {
		return fmt.Errorf("init client: %w", err)
	}

	var body io.Reader
	if s.body != "" {
		body = strings.NewReader(s.body)
	}
	req, err := http.NewRequest(s.method, s.url, body)
	if err != nil {
		return err
	}
	s.setHeaders(req)
	req = req.WithContext(ctx)

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("unsuccessful status code %d", resp.StatusCode)
	}

	_, err = io.Copy(f, resp.Body)
	return err
}

func (*HttpDataSynchronizer) Close(context.Context) {
	// No resources to close for HTTP synchronizer
}

func (s *HttpDataSynchronizer) initClient(ctx context.Context) error {
	if s.client != nil {
		// We only do this once.  It cannot be done in the constructor
		// since we want to return an error if need be.
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

func (s *HttpDataSynchronizer) setHeaders(req *http.Request) {
	for name, value := range s.headers {
		if value, ok := value.(string); ok && value != "" {
			req.Header.Set(name, value)
		}
	}
}

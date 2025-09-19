package httpsync

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/styrainc/opa-control-plane/internal/config"
)

// HttpDataSynchronizer is a struct that implements the Synchronizer interface for downloading JSON from HTTP endpoints.
type HttpDataSynchronizer struct {
	path        string // The path where the data will be saved
	url         string
	headers     map[string]interface{} // Headers to include in the HTTP request
	credentials *config.SecretRef
}

func New(path string, url string, headers map[string]interface{}, credentials *config.SecretRef) *HttpDataSynchronizer {
	return &HttpDataSynchronizer{path: path, url: url, headers: headers, credentials: credentials}
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

	req, err := http.NewRequest("GET", s.url, nil)
	if err != nil {
		return err
	}

	err = s.setHeaders(ctx, req)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func (*HttpDataSynchronizer) Close(context.Context) {
	// No resources to close for HTTP synchronizer
}

func (s *HttpDataSynchronizer) setHeaders(ctx context.Context, req *http.Request) error {
	for name, value := range s.headers {
		if value, ok := value.(string); ok && value != "" {
			req.Header.Set(name, value)
		}
	}

	if s.credentials == nil {
		return nil
	}

	value, err := s.credentials.Resolve(ctx)
	if err != nil {
		return err
	}

	switch value := value.(type) {
	case config.SecretBasicAuth:
		req.SetBasicAuth(value.Username, value.Password)
	case config.SecretTokenAuth:
		req.Header.Set("Authorization", "Bearer "+value.Token)
	default:
		return fmt.Errorf("unsupported authentication type: %T", value)
	}
	return nil
}

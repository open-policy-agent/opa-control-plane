package httpsync

import (
	"errors"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/httpsync"
	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
)

// NewFromHTTPConfig creates a new HTTP Synchronizer using a map-based configuration.
// This is the recommended constructor for external projects.
//
// The httpConfig map should contain the following fields:
//   - "url" (string, required): HTTP endpoint URL
//   - "method" (string, optional): HTTP method (default: "GET")
//   - "body" (string, optional): Request body (for POST/PUT)
//   - "headers" (map[string]any, optional): Custom HTTP headers
//   - "credential" (string, optional): Name of credential to use for authentication
//
// The path parameter specifies where to save the downloaded data.
//
// The secretProvider is required if credentials are needed. The provider will be called
// with the credential name to retrieve the actual credentials.
//
// Example usage:
//
//	httpConfig := map[string]any{
//	    "url":        "https://api.example.com/data.json",
//	    "method":     "GET",
//	    "headers":    map[string]any{"Accept": "application/json"},
//	    "credential": "api-bearer-token",
//	}
//	provider := myorg.NewWhisperSecretProvider(whisperClient)
//	syncer, err := httpsync.NewFromHTTPConfig("/path/to/save.json", httpConfig, provider)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	err = syncer.Execute(ctx)
func NewFromHTTPConfig(path string, httpConfig map[string]any, provider pkgsync.SecretProvider) (*httpsync.HttpDataSynchronizer, error) {
	url, ok := httpConfig["url"].(string)
	if !ok || url == "" {
		return nil, errors.New("http config: 'url' field is required")
	}

	method := "GET"
	if m, ok := httpConfig["method"].(string); ok && m != "" {
		method = m
	}

	body := ""
	if b, ok := httpConfig["body"].(string); ok {
		body = b
	}

	headers, _ := httpConfig["headers"].(map[string]any)

	var credentials *config.SecretRef
	if credName, ok := httpConfig["credential"].(string); ok && credName != "" {
		credentials = &config.SecretRef{Name: credName}
	}

	syncer := httpsync.New(path, url, method, body, headers, credentials)
	if provider != nil {
		syncer = syncer.WithSecretProvider(provider)
	}

	return syncer, nil
}

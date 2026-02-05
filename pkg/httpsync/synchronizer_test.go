package httpsync_test

import (
	"context"
	"errors"
	"testing"

	"github.com/open-policy-agent/opa-control-plane/pkg/httpsync"
)

// mockSecretProvider implements httpsync.SecretProvider for testing
type mockSecretProvider struct {
	secrets map[string]map[string]any
}

func (m *mockSecretProvider) GetSecret(ctx context.Context, name string) (map[string]any, error) {
	if secret, ok := m.secrets[name]; ok {
		return secret, nil
	}
	return nil, errors.New("secret not found: " + name)
}

func TestNewFromHTTPConfig_Success(t *testing.T) {
	provider := &mockSecretProvider{
		secrets: map[string]map[string]any{
			"api-token": {
				"type":  "bearer",
				"token": "test-token-123",
			},
		},
	}

	config := map[string]any{
		"url":        "https://api.example.com/data",
		"method":     "GET",
		"credential": "api-token",
		"headers": map[string]any{
			"Accept": "application/json",
		},
	}

	syncer, err := httpsync.NewFromHTTPConfig("/tmp/data.json", config, provider)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if syncer == nil {
		t.Fatal("expected non-nil synchronizer")
	}
}

func TestNewFromHTTPConfig_RequiresURL(t *testing.T) {
	config := map[string]any{
		"method": "GET",
	}

	_, err := httpsync.NewFromHTTPConfig("/tmp/data.json", config, nil)
	if err == nil {
		t.Fatal("expected error for missing URL")
	}

	expected := "http config: 'url' field is required"
	if err.Error() != expected {
		t.Fatalf("expected error %q, got %q", expected, err.Error())
	}
}

func TestNewFromHTTPConfig_DefaultMethod(t *testing.T) {
	config := map[string]any{
		"url": "https://api.example.com/data",
		// method not specified, should default to GET
	}

	syncer, err := httpsync.NewFromHTTPConfig("/tmp/data.json", config, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if syncer == nil {
		t.Fatal("expected non-nil synchronizer")
	}
}

func TestNewFromHTTPConfig_NoCredentials(t *testing.T) {
	config := map[string]any{
		"url":    "https://api.example.com/data",
		"method": "POST",
		"body":   `{"key": "value"}`,
	}

	syncer, err := httpsync.NewFromHTTPConfig("/tmp/data.json", config, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if syncer == nil {
		t.Fatal("expected non-nil synchronizer")
	}
}

func TestNewFromHTTPConfig_WithHeaders(t *testing.T) {
	config := map[string]any{
		"url":    "https://api.example.com/data",
		"method": "GET",
		"headers": map[string]any{
			"Accept":        "application/json",
			"Authorization": "Bearer token",
		},
	}

	syncer, err := httpsync.NewFromHTTPConfig("/tmp/data.json", config, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if syncer == nil {
		t.Fatal("expected non-nil synchronizer")
	}
}

func TestMockSecretProvider_BearerToken(t *testing.T) {
	provider := &mockSecretProvider{
		secrets: map[string]map[string]any{
			"bearer-cred": {
				"type":  "bearer",
				"token": "abc123",
			},
		},
	}

	secret, err := provider.GetSecret(context.Background(), "bearer-cred")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if secret["type"] != "bearer" {
		t.Errorf("expected type 'bearer', got %v", secret["type"])
	}
	if secret["token"] != "abc123" {
		t.Errorf("expected token 'abc123', got %v", secret["token"])
	}
}

func TestMockSecretProvider_BasicAuth(t *testing.T) {
	provider := &mockSecretProvider{
		secrets: map[string]map[string]any{
			"basic-cred": {
				"type":     "basic",
				"username": "user",
				"password": "pass",
			},
		},
	}

	secret, err := provider.GetSecret(context.Background(), "basic-cred")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if secret["type"] != "basic" {
		t.Errorf("expected type 'basic', got %v", secret["type"])
	}
}

func TestMockSecretProvider_NotFound(t *testing.T) {
	provider := &mockSecretProvider{
		secrets: map[string]map[string]any{},
	}

	_, err := provider.GetSecret(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent secret")
	}
}

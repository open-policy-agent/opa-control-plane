package httpsync_test

import (
	"context"
	"errors"
	"testing"

	"github.com/open-policy-agent/opa-control-plane/pkg/httpsync"
	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
)

// mockSecretProvider implements pkgsync.SecretProvider for testing
type mockSecretProvider struct {
	secrets map[string]map[string]any
}

func (m *mockSecretProvider) GetSecret(ctx context.Context, name string) (map[string]any, error) {
	if secret, ok := m.secrets[name]; ok {
		return secret, nil
	}
	return nil, errors.New("secret not found: " + name)
}

func TestNewFromHTTPConfig(t *testing.T) {
	provider := &mockSecretProvider{
		secrets: map[string]map[string]any{
			"api-token": {
				"type":  "bearer",
				"token": "test-token-123",
			},
		},
	}

	tests := []struct {
		name        string
		config      map[string]any
		provider    pkgsync.SecretProvider
		expectError bool
		errorMsg    string
	}{
		{
			name: "success with credentials",
			config: map[string]any{
				"url":        "https://api.example.com/data",
				"method":     "GET",
				"credential": "api-token",
				"headers": map[string]any{
					"Accept": "application/json",
				},
			},
			provider:    provider,
			expectError: false,
		},
		{
			name: "requires URL",
			config: map[string]any{
				"method": "GET",
			},
			provider:    nil,
			expectError: true,
			errorMsg:    "http config: 'url' field is required",
		},
		{
			name: "default method",
			config: map[string]any{
				"url": "https://api.example.com/data",
			},
			provider:    nil,
			expectError: false,
		},
		{
			name: "no credentials",
			config: map[string]any{
				"url":    "https://api.example.com/data",
				"method": "POST",
				"body":   `{"key": "value"}`,
			},
			provider:    nil,
			expectError: false,
		},
		{
			name: "with headers",
			config: map[string]any{
				"url":    "https://api.example.com/data",
				"method": "GET",
				"headers": map[string]any{
					"Accept":        "application/json",
					"Authorization": "Bearer token",
				},
			},
			provider:    nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syncer, err := httpsync.NewFromHTTPConfig("/tmp/data.json", tt.config, tt.provider)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Fatalf("expected error %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if syncer == nil {
				t.Fatal("expected non-nil synchronizer")
			}
		})
	}
}

func TestMockSecretProvider(t *testing.T) {
	tests := []struct {
		name        string
		secrets     map[string]map[string]any
		secretName  string
		expectError bool
		validate    func(t *testing.T, secret map[string]any)
	}{
		{
			name: "bearer token",
			secrets: map[string]map[string]any{
				"bearer-cred": {
					"type":  "bearer",
					"token": "abc123",
				},
			},
			secretName:  "bearer-cred",
			expectError: false,
			validate: func(t *testing.T, secret map[string]any) {
				if secret["type"] != "bearer" {
					t.Errorf("expected type 'bearer', got %v", secret["type"])
				}
				if secret["token"] != "abc123" {
					t.Errorf("expected token 'abc123', got %v", secret["token"])
				}
			},
		},
		{
			name: "basic auth",
			secrets: map[string]map[string]any{
				"basic-cred": {
					"type":     "basic",
					"username": "user",
					"password": "pass",
				},
			},
			secretName:  "basic-cred",
			expectError: false,
			validate: func(t *testing.T, secret map[string]any) {
				if secret["type"] != "basic" {
					t.Errorf("expected type 'basic', got %v", secret["type"])
				}
			},
		},
		{
			name:        "not found",
			secrets:     map[string]map[string]any{},
			secretName:  "nonexistent",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockSecretProvider{secrets: tt.secrets}

			secret, err := provider.GetSecret(t.Context(), tt.secretName)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validate != nil {
				tt.validate(t, secret)
			}
		})
	}
}

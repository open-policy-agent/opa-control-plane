package gitsync_test

import (
	"context"
	"errors"
	"testing"

	"github.com/open-policy-agent/opa-control-plane/pkg/gitsync"
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

func TestNewFromGitConfig(t *testing.T) {
	provider := &mockSecretProvider{
		secrets: map[string]map[string]any{
			"github-token": {
				"type":  "token_auth",
				"token": "ghp_test123",
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
			name: "success with reference and credentials",
			config: map[string]any{
				"repo":       "https://github.com/myorg/policies.git",
				"reference":  "main",
				"credential": "github-token",
			},
			provider:    provider,
			expectError: false,
		},
		{
			name: "requires repo",
			config: map[string]any{
				"reference": "main",
			},
			provider:    nil,
			expectError: true,
			errorMsg:    "git config: 'repo' field is required",
		},
		{
			name: "empty repo",
			config: map[string]any{
				"repo": "",
			},
			provider:    nil,
			expectError: true,
			errorMsg:    "git config: 'repo' field is required",
		},
		{
			name: "success with commit",
			config: map[string]any{
				"repo":   "https://github.com/myorg/policies.git",
				"commit": "abc123def456",
			},
			provider:    nil,
			expectError: false,
		},
		{
			name: "no credentials",
			config: map[string]any{
				"repo":      "https://github.com/myorg/public-repo.git",
				"reference": "main",
			},
			provider:    nil,
			expectError: false,
		},
		{
			name: "minimal config",
			config: map[string]any{
				"repo": "https://github.com/myorg/policies.git",
			},
			provider:    nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syncer, err := gitsync.NewFromGitConfig("/tmp/test-repo", tt.config, "test-source", tt.provider)

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
			name: "github token",
			secrets: map[string]map[string]any{
				"github-token": {
					"type":  "token_auth",
					"token": "ghp_abc123",
				},
			},
			secretName:  "github-token",
			expectError: false,
			validate: func(t *testing.T, secret map[string]any) {
				if secret["type"] != "token_auth" {
					t.Errorf("expected type 'token_auth', got %v", secret["type"])
				}
				if secret["token"] != "ghp_abc123" {
					t.Errorf("expected token 'ghp_abc123', got %v", secret["token"])
				}
			},
		},
		{
			name: "ssh key",
			secrets: map[string]map[string]any{
				"ssh-key": {
					"type":       "ssh_key",
					"key":        "-----BEGIN RSA PRIVATE KEY-----",
					"passphrase": "secret",
				},
			},
			secretName:  "ssh-key",
			expectError: false,
			validate: func(t *testing.T, secret map[string]any) {
				if secret["type"] != "ssh_key" {
					t.Errorf("expected type 'ssh_key', got %v", secret["type"])
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

			secret, err := provider.GetSecret(context.Background(), tt.secretName)

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

package config_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
)

// TestSecretOIDCClientCredentialsClientAssertion covers the configuration
// errors of client assertion based client authentication. The error surfaces
// when a token is requested, which is where the configuration is resolved.
func TestSecretOIDCClientCredentialsClientAssertion(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	emptyFile := filepath.Join(dir, "empty")
	if err := os.WriteFile(emptyFile, []byte("  \n"), 0o600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	tests := []struct {
		name        string
		value       map[string]any
		expectedErr string
	}{
		{
			name: "neither client_secret nor client_assertion_file",
			value: map[string]any{
				"type":           "oidc_client_credentials",
				"token_endpoint": "https://example.invalid/token",
				"client_id":      "test_client",
			},
			expectedErr: "either client_secret or client_assertion_file is required",
		},
		{
			name: "both client_secret and client_assertion_file",
			value: map[string]any{
				"type":                  "oidc_client_credentials",
				"token_endpoint":        "https://example.invalid/token",
				"client_id":             "test_client",
				"client_secret":         "test_secret",
				"client_assertion_file": emptyFile,
			},
			expectedErr: "client_secret and client_assertion_file are mutually exclusive",
		},
		{
			name: "client_assertion_file does not exist",
			value: map[string]any{
				"type":                  "oidc_client_credentials",
				"token_endpoint":        "https://example.invalid/token",
				"client_id":             "test_client",
				"client_assertion_file": filepath.Join(dir, "missing"),
			},
			expectedErr: "failed to read client_assertion_file",
		},
		{
			name: "client_assertion_file is empty",
			value: map[string]any{
				"type":                  "oidc_client_credentials",
				"token_endpoint":        "https://example.invalid/token",
				"client_id":             "test_client",
				"client_assertion_file": emptyFile,
			},
			expectedErr: "is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := config.Secret{Name: "test_secret", Value: tt.value}

			resolved, err := secret.Typed(ctx)
			if err != nil {
				t.Fatalf("failed to resolve secret: %v", err)
			}

			creds, ok := resolved.(*config.SecretOIDCClientCredentials)
			if !ok {
				t.Fatalf("unexpected secret type: %T", resolved)
			}

			_, err = creds.Token(ctx)
			if err == nil {
				t.Fatal("expected an error, got none")
			}
			if !strings.Contains(err.Error(), tt.expectedErr) {
				t.Fatalf("expected error containing %q, got: %v", tt.expectedErr, err)
			}
		})
	}
}

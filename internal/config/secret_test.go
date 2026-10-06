package config_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// TestSecretOIDCClientCredentialsClientAssertionRotation verifies that the HTTP
// client returned by Client() re-reads the client assertion when it refreshes
// the access token, rather than reusing the assertion read at construction
// time. The token endpoint returns a token whose lifetime is below the
// oauth2 reuse threshold, so every request forces a refresh and the test does
// not have to wait for a real expiry.
func TestSecretOIDCClientCredentialsClientAssertionRotation(t *testing.T) {
	ctx := context.Background()

	assertionFile := filepath.Join(t.TempDir(), "azure-identity-token")
	if err := os.WriteFile(assertionFile, []byte("first.assertion.jwt"), 0o600); err != nil {
		t.Fatalf("failed to write assertion file: %v", err)
	}

	var (
		mu         sync.Mutex
		assertions []string
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		mu.Lock()
		assertions = append(assertions, r.Form.Get("client_assertion"))
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access_" + r.Form.Get("client_assertion"),
			"token_type":   "Bearer",
			"expires_in":   1,
		})
	})
	mux.HandleFunc("/resource", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	secret := config.Secret{
		Name: "test_secret",
		Value: map[string]any{
			"type":                  "oidc_client_credentials",
			"token_endpoint":        server.URL + "/token",
			"client_id":             "test_client",
			"client_assertion_file": assertionFile,
		},
	}

	resolved, err := secret.Typed(ctx)
	if err != nil {
		t.Fatalf("failed to resolve secret: %v", err)
	}

	creds, ok := resolved.(*config.SecretOIDCClientCredentials)
	if !ok {
		t.Fatalf("unexpected secret type: %T", resolved)
	}

	client, err := creds.Client(ctx)
	if err != nil {
		t.Fatalf("failed to build client: %v", err)
	}

	get := func() {
		t.Helper()

		resp, err := client.Get(server.URL + "/resource")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status: %d", resp.StatusCode)
		}
	}

	get()

	// The platform rewrites the projected token in place.
	if err := os.WriteFile(assertionFile, []byte("second.assertion.jwt"), 0o600); err != nil {
		t.Fatalf("failed to rotate assertion file: %v", err)
	}

	get()

	mu.Lock()
	defer mu.Unlock()

	want := []string{"first.assertion.jwt", "second.assertion.jwt"}
	if len(assertions) != len(want) {
		t.Fatalf("expected %d token requests, got %d: %v", len(want), len(assertions), assertions)
	}
	for i := range want {
		if assertions[i] != want[i] {
			t.Errorf("token request %d: expected assertion %q, got %q", i, want[i], assertions[i])
		}
	}
}

// TestSecretOIDCClientCredentialsClientAssertionReadFailure verifies that a
// client assertion that is temporarily unreadable -- as can happen if the file
// is missing while the platform rotates it -- surfaces a clear error and does
// not leave the client permanently broken once the file reappears.
func TestSecretOIDCClientCredentialsClientAssertionReadFailure(t *testing.T) {
	ctx := context.Background()

	assertionFile := filepath.Join(t.TempDir(), "azure-identity-token")
	if err := os.WriteFile(assertionFile, []byte("first.assertion.jwt"), 0o600); err != nil {
		t.Fatalf("failed to write assertion file: %v", err)
	}

	var (
		mu         sync.Mutex
		assertions []string
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		mu.Lock()
		assertions = append(assertions, r.Form.Get("client_assertion"))
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access_" + r.Form.Get("client_assertion"),
			"token_type":   "Bearer",
			"expires_in":   1,
		})
	})
	mux.HandleFunc("/resource", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	secret := config.Secret{
		Name: "test_secret",
		Value: map[string]any{
			"type":                  "oidc_client_credentials",
			"token_endpoint":        server.URL + "/token",
			"client_id":             "test_client",
			"client_assertion_file": assertionFile,
		},
	}

	resolved, err := secret.Typed(ctx)
	if err != nil {
		t.Fatalf("failed to resolve secret: %v", err)
	}

	creds, ok := resolved.(*config.SecretOIDCClientCredentials)
	if !ok {
		t.Fatalf("unexpected secret type: %T", resolved)
	}

	client, err := creds.Client(ctx)
	if err != nil {
		t.Fatalf("failed to build client: %v", err)
	}

	resp, err := client.Get(server.URL + "/resource")
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	resp.Body.Close()

	// The assertion disappears, as it may briefly during rotation.
	if err := os.Remove(assertionFile); err != nil {
		t.Fatalf("failed to remove assertion file: %v", err)
	}

	if _, err := client.Get(server.URL + "/resource"); err == nil {
		t.Fatal("expected the request to fail while the assertion is unreadable")
	} else if !strings.Contains(err.Error(), "client_assertion_file") {
		t.Errorf("expected an error naming client_assertion_file, got: %v", err)
	}

	// Once the assertion is back, the same client must recover without being rebuilt.
	if err := os.WriteFile(assertionFile, []byte("second.assertion.jwt"), 0o600); err != nil {
		t.Fatalf("failed to restore assertion file: %v", err)
	}

	resp, err = client.Get(server.URL + "/resource")
	if err != nil {
		t.Fatalf("request after recovery failed: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	want := []string{"first.assertion.jwt", "second.assertion.jwt"}
	if len(assertions) != len(want) {
		t.Fatalf("expected %d token requests, got %d: %v", len(want), len(assertions), assertions)
	}
	for i := range want {
		if assertions[i] != want[i] {
			t.Errorf("token request %d: expected assertion %q, got %q", i, want[i], assertions[i])
		}
	}
}

// TestSecretOIDCClientCredentialsClientSecretUnchanged guards the client_secret
// path against regressions from the client assertion support: the credential
// must still be sent as a client secret, no assertion parameters may appear,
// and the access token must still be cached across requests.
func TestSecretOIDCClientCredentialsClientSecretUnchanged(t *testing.T) {
	ctx := context.Background()

	var (
		mu               sync.Mutex
		tokenRequests    int
		sawAssertionType bool
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// The client secret may arrive either as basic auth or in the body,
		// depending on the auth style the library negotiates.
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok {
			clientID, clientSecret = r.Form.Get("client_id"), r.Form.Get("client_secret")
		}

		mu.Lock()
		tokenRequests++
		if r.Form.Get("client_assertion_type") != "" || r.Form.Get("client_assertion") != "" {
			sawAssertionType = true
		}
		mu.Unlock()

		if clientID != "test_client" || clientSecret != "test_secret" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access_token_value",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/resource", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	secret := config.Secret{
		Name: "test_secret",
		Value: map[string]any{
			"type":           "oidc_client_credentials",
			"token_endpoint": server.URL + "/token",
			"client_id":      "test_client",
			"client_secret":  "test_secret",
		},
	}

	resolved, err := secret.Typed(ctx)
	if err != nil {
		t.Fatalf("failed to resolve secret: %v", err)
	}

	creds, ok := resolved.(*config.SecretOIDCClientCredentials)
	if !ok {
		t.Fatalf("unexpected secret type: %T", resolved)
	}

	client, err := creds.Client(ctx)
	if err != nil {
		t.Fatalf("failed to build client: %v", err)
	}

	for i := range 2 {
		resp, err := client.Get(server.URL + "/resource")
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()
	}

	mu.Lock()
	defer mu.Unlock()

	if tokenRequests != 1 {
		t.Errorf("expected the access token to be cached across requests (1 token request), got %d", tokenRequests)
	}
	if sawAssertionType {
		t.Error("client assertion parameters must not be sent for a client_secret credential")
	}
}

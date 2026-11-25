package config_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
)

// TestSecretOIDCClientCredentialsClientAssertion covers the configuration
// errors of client assertion based client authentication. The error surfaces
// when a token is requested, which is where the configuration is resolved.
func TestSecretOIDCClientCredentialsClientAssertion(t *testing.T) {
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
			creds := oidcCredentials(t, tt.value)

			_, err := creds.Token(t.Context())
			if err == nil {
				t.Fatal("expected an error, got none")
			}
			if !strings.Contains(err.Error(), tt.expectedErr) {
				t.Fatalf("expected error containing %q, got: %v", tt.expectedErr, err)
			}
		})
	}
}

func oidcCredentials(t *testing.T, value map[string]any) *config.SecretOIDCClientCredentials {
	t.Helper()

	secret := config.Secret{Name: "test_secret", Value: value}

	resolved, err := secret.Typed(t.Context())
	if err != nil {
		t.Fatalf("failed to resolve secret: %v", err)
	}

	creds, ok := resolved.(*config.SecretOIDCClientCredentials)
	if !ok {
		t.Fatalf("unexpected secret type: %T", resolved)
	}

	return creds
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

// newAssertionServer serves /token, issuing access tokens that live for
// expiresIn seconds, and /resource. The returned function reports the client
// assertions received so far. An expiresIn below the oauth2 reuse threshold
// forces a token refresh on every request.
func newAssertionServer(t *testing.T, expiresIn int) (*httptest.Server, func() []string) {
	t.Helper()

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
			"expires_in":   expiresIn,
		})
	})
	mux.HandleFunc("/resource", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(assertions)
	}
}

func assertionCredentials(t *testing.T, server *httptest.Server, assertionFile string) *config.SecretOIDCClientCredentials {
	t.Helper()

	return oidcCredentials(t, map[string]any{
		"type":                  "oidc_client_credentials",
		"token_endpoint":        server.URL + "/token",
		"client_id":             "test_client",
		"client_assertion_file": assertionFile,
	})
}

func assertAssertions(t *testing.T, got, want []string) {
	t.Helper()

	if !slices.Equal(got, want) {
		t.Fatalf("expected token requests with assertions %v, got %v", want, got)
	}
}

// TestSecretOIDCClientCredentialsClientAssertionRotation verifies that the HTTP
// client returned by Client() re-reads the client assertion when it refreshes
// the access token, rather than reusing the assertion read at construction time.
func TestSecretOIDCClientCredentialsClientAssertionRotation(t *testing.T) {
	assertionFile := filepath.Join(t.TempDir(), "azure-identity-token")
	writeFile(t, assertionFile, "first.assertion.jwt")

	server, assertions := newAssertionServer(t, 1)

	client, err := assertionCredentials(t, server, assertionFile).Client(t.Context())
	if err != nil {
		t.Fatalf("failed to build client: %v", err)
	}

	get := func() {
		t.Helper()

		resp, err := client.Get(server.URL + "/resource")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status: %d", resp.StatusCode)
		}
	}

	get()
	writeFile(t, assertionFile, "second.assertion.jwt")
	get()

	assertAssertions(t, assertions(), []string{"first.assertion.jwt", "second.assertion.jwt"})
}

// TestSecretOIDCClientCredentialsClientAssertionReadFailure verifies that an
// unreadable assertion, as during rotation, surfaces a clear error and the
// client recovers once the file reappears.
func TestSecretOIDCClientCredentialsClientAssertionReadFailure(t *testing.T) {
	assertionFile := filepath.Join(t.TempDir(), "azure-identity-token")
	writeFile(t, assertionFile, "first.assertion.jwt")

	server, assertions := newAssertionServer(t, 1)

	client, err := assertionCredentials(t, server, assertionFile).Client(t.Context())
	if err != nil {
		t.Fatalf("failed to build client: %v", err)
	}

	resp, err := client.Get(server.URL + "/resource")
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	resp.Body.Close()

	if err := os.Remove(assertionFile); err != nil {
		t.Fatalf("failed to remove assertion file: %v", err)
	}

	if _, err := client.Get(server.URL + "/resource"); err == nil {
		t.Fatal("expected the request to fail while the assertion is unreadable")
	} else if !strings.Contains(err.Error(), "client_assertion_file") {
		t.Errorf("expected an error naming client_assertion_file, got: %v", err)
	}

	writeFile(t, assertionFile, "second.assertion.jwt")

	resp, err = client.Get(server.URL + "/resource")
	if err != nil {
		t.Fatalf("request after recovery failed: %v", err)
	}
	resp.Body.Close()

	assertAssertions(t, assertions(), []string{"first.assertion.jwt", "second.assertion.jwt"})
}

// TestSecretOIDCClientCredentialsClientSecretUnchanged guards the client_secret
// path against regressions from the client assertion support: the credential
// must still be sent as a client secret, no assertion parameters may appear,
// and the access token must still be cached across requests.
func TestSecretOIDCClientCredentialsClientSecretUnchanged(t *testing.T) {
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

	creds := oidcCredentials(t, map[string]any{
		"type":           "oidc_client_credentials",
		"token_endpoint": server.URL + "/token",
		"client_id":      "test_client",
		"client_secret":  "test_secret",
	})

	client, err := creds.Client(t.Context())
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

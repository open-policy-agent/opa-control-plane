package httpsync

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
)

func TestHTTPDataSynchronizer(t *testing.T) {
	contents := `{"key": "value"}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		_, err := w.Write([]byte(contents))
		if err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	file := path.Join(t.TempDir(), "foo/test.json")
	synchronizer := New(file, ts.URL, "", "", nil, nil)
	err := synchronizer.Execute(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("expected no error while reading file, got: %v", err)
	}

	if !bytes.Equal(data, []byte(contents)) {
		t.Fatal("downloaded data does not match expected contents")
	}
}

func TestHTTPDataSynchronizer_Error_BadStatusCode(t *testing.T) {
	currentContents := `{ "previous": "content" }`
	errorResponseBody := `{"error": "value"}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		w.WriteHeader(http.StatusBadRequest)
		_, err := w.Write([]byte(errorResponseBody))
		if err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	dir := path.Join(t.TempDir(), "foo")
	err := os.Mkdir(dir, 0755)
	if err != nil {
		t.Fatalf("failed to create base dir: %s", err.Error())
	}
	file := path.Join(dir, "test.json")
	err = os.WriteFile(file, []byte(currentContents), 0666)
	if err != nil {
		t.Fatalf("failed to write current contents: %s", err.Error())
	}

	synchronizer := New(file, ts.URL, "", "", nil, nil)
	err = synchronizer.Execute(context.Background())
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	expectedError := "unsuccessful status code 400"
	if err.Error() != expectedError {
		t.Fatalf("expected error %q, got %q", expectedError, err.Error())
	}

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("expected no error while reading file, got: %v", err)
	}

	if len(data) != 0 {
		t.Fatal("downloaded data should be empty after an error")
	}
}

func TestHTTPDataSynchronizer_Post(t *testing.T) {

	payloadContents := `{"data": "data"}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(r.Body)
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusInternalServerError)
			return
		}
		if buf.String() != payloadContents {
			http.Error(w, "unexpected request body", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write([]byte(payloadContents))
		if err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	file := path.Join(t.TempDir(), "foo/test.json")
	synchronizer := New(file, ts.URL, "POST", payloadContents, nil, nil)
	err := synchronizer.Execute(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("expected no error while reading file, got: %v", err)
	}

	if !bytes.Equal(data, []byte(payloadContents)) {
		t.Fatal("downloaded data does not match expected contents")
	}
}

func TestHTTPDataSynchronizer_WithAuthTokenHeaders(t *testing.T) {
	payloadContents := `{"data": "data"}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(r.Body)
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusInternalServerError)
			return
		}
		if buf.String() != payloadContents {
			http.Error(w, "unexpected request body", http.StatusBadRequest)
			return
		}

		if r.Header.Get("Authorization") != "Bearer secret_token" {
			http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write([]byte(payloadContents))
		if err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	headers := map[string]any{
		"content-type": "application/json",
	}
	secret := config.Secret{
		Name: "authName",
		Value: map[string]any{
			"type":  "token_auth",
			"token": "secret_token",
		},
	}
	file := path.Join(t.TempDir(), "foo/test.json")
	synchronizer := New(file, ts.URL, "POST", payloadContents, headers, secret.Ref())
	err := synchronizer.Execute(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("expected no error while reading file, got: %v", err)
	}

	if !bytes.Equal(data, []byte(payloadContents)) {
		t.Fatal("downloaded data does not match expected contents")
	}
}

func TestHTTPDataSynchronizer_WithBasicAuthHeaders(t *testing.T) {
	contents := `{"key": "value"}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		_, err := w.Write([]byte(contents))
		if err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	file := path.Join(t.TempDir(), "foo/test.json")
	secret := config.Secret{
		Name: "authName",
		Value: map[string]any{
			"type":     "basic_auth",
			"username": "user",
			"password": "pass",
		},
	}

	synchronizer := New(file, ts.URL, "", "", nil, secret.Ref())
	err := synchronizer.Execute(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("expected no error while reading file, got: %v", err)
	}

	if !bytes.Equal(data, []byte(contents)) {
		t.Fatal("downloaded data does not match expected contents")
	}
}

func TestHTTPDataSynchronizer_WithInvalidAuthHeaders(t *testing.T) {
	contents := `{"key": "value"}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		_, err := w.Write([]byte(contents))
		if err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	file := path.Join(t.TempDir(), "foo/test.json")
	secret := config.Secret{
		Name: "authName",
		Value: map[string]any{
			"type":     "invalid_auth",
			"username": "user",
			"password": "pass",
		},
	}

	synchronizer := New(file, ts.URL, "", "", nil, secret.Ref())
	err := synchronizer.Execute(context.Background())
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	expectedError := "init client: unknown secret type \"invalid_auth\""
	if err.Error() != expectedError {
		t.Fatalf("expected error %q, got %q", expectedError, err.Error())
	}

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("expected no error while reading file, got: %v", err)
	}

	if len(data) != 0 {
		t.Fatal("downloaded data should be empty after an error")
	}
}

// mockOIDCProvider simulates an OIDC provider for client credentials flow
func mockOIDCProvider(clientID, clientSecret string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "client_credentials" {
			http.Error(w, "Unsupported grant type", http.StatusBadRequest)
			return
		}
		if r.Form.Get("client_id") != clientID || r.Form.Get("client_secret") != clientSecret {
			http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
			return
		}

		requestedScopes := r.Form.Get("scope")
		tokenResponse := map[string]any{
			"access_token": "mock_access_token_" + strings.ReplaceAll(requestedScopes, " ", "_"),
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        requestedScopes,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse)
	})

	return httptest.NewServer(mux)
}

func TestHTTPDataSynchronizer_OIDC_ClientCredentials(t *testing.T) {
	oidc := mockOIDCProvider("foobear", "1234")
	t.Cleanup(oidc.Close)

	contents := `{"key": "value"}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		hdr := r.Header.Get("Authorization")
		if hdr != "Bearer mock_access_token_A_B" {
			t.Logf("unexpected header: %q", hdr)
			http.Error(w, "failed to write response", http.StatusUnauthorized)
			return
		}

		_, err := w.Write([]byte(contents))
		if err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(ts.Close)

	secret := config.Secret{Name: "oidc",
		Value: map[string]any{
			"type":           "oidc_client_credentials",
			"token_endpoint": oidc.URL + "/token",
			"client_id":      "foobear",
			"client_secret":  "1234",
			"scopes":         []string{"A", "B"},
		},
	}

	file := path.Join(t.TempDir(), "foo/test.json")
	extra := map[string]any{"abc": "def"}
	synchronizer := New(file, ts.URL, "GET", "", extra, secret.Ref())
	err := synchronizer.Execute(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("expected no error while reading file, got: %v", err)
	}

	if !bytes.Equal(data, []byte(contents)) {
		t.Fatal("downloaded data does not match expected contents")
	}
}

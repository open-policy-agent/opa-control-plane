package httpsync

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
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
	expectedError := "unknown secret type \"invalid_auth\""
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

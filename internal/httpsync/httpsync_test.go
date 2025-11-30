package httpsync

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"
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

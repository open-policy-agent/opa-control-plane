package service_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"text/template"

	"github.com/go-git/go-git/v5"
	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/logging"
	"github.com/open-policy-agent/opa-control-plane/internal/service"
)

func TestUnconfiguredSecretHandling(t *testing.T) {

	bs := fmt.Appendf(nil, `{
		bundles: {
			test_bundle: {
				object_storage: {
					filesystem: {
						path: %q
					}
				},
				requirements: [
					{source: test_src}
				]
			}
		},
		sources: {
			test_src: {
				git: {
					repo: https://example.com/repo.git,
					credentials: test_creds,
					reference: refs/heads/main,
				}
			}
		},
		secrets: {
			test_creds: {} # not configured
		}
	}`, filepath.Join(t.TempDir(), "bundles"))

	report := oneshot(t, bs, t.TempDir()).Report()
	status := report.Bundles["test_bundle"]

	if status.State != service.BuildStateSyncFailed {
		t.Fatal("expected sync failure state")
	} else if status.Message != `source "test_src": git synchronizer: https://example.com/repo.git: secret "test_creds" is not configured` {
		t.Fatal("unexpected status message")
	}
}

func TestRequirementsWithOverrides(t *testing.T) {

	tempDir := t.TempDir()

	tmpl := `{
		bundles: {
			test_bundle: {
				object_storage: {
					filesystem: {
						path: "{{ printf "%s/%s" .Path "bundles.tar.gz" }}",
					}
				},
				requirements: [
					{source: test_src, git: {commit: "{{ .GitHash }}"}},
				],
			},
		},
		sources: {
			test_src: {
				git: {
					repo: "{{ printf "%s/%s" .Path "remotegit" }}",
					reference: refs/heads/master,
				},
			},
		},
	}`

	const initialContent = `package foo

		p := 7`

	h := writeGitRepo(t, filepath.Join(tempDir, "remotegit"), map[string]string{
		"foo.rego": initialContent,
	}, nil)

	writeGitFiles(t, filepath.Join(tempDir, "remotegit"), map[string]string{
		"foo.rego": `package foo

		p := 8`,
	})

	bs := render(t, tmpl, struct {
		Path    string
		GitHash string
	}{
		Path:    tempDir,
		GitHash: h.String(),
	})

	svc := oneshot(t, bs, tempDir)
	_ = svc.Report()

	glob := filepath.Join(tempDir, "data", "*", "sources", "test_src", "repo", "foo.rego")
	matches, err := filepath.Glob(glob)
	if err != nil {
		t.Fatalf("Failed to glob for foo.rego: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("No foo.rego file found matching pattern: %s", glob)
	}

	filePath := matches[0]
	foo, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", filePath, err)
	}
	if string(foo) != initialContent {
		t.Fatal("unexpected file content")
	}
}

func TestRequirementsWithConflictingOverrides(t *testing.T) {

	tempDir := t.TempDir()

	tmpl := `{
		bundles: {
			test_bundle: {
				object_storage: {
					filesystem: {
						path: "{{ printf "%s/%s" .Path "bundles.tar.gz" }}",
					}
				},
				requirements: [
					{source: test_src, git: {commit: "{{ .GitHash }}"}},
					{source: other_src},
				],
			},
		},
		sources: {
			test_src: {
				git: {
					repo: "{{ printf "%s/%s" .Path "remotegit" }}",
					reference: refs/heads/master,
				},
			},
			other_src: {
				requirements: [
					{source: test_src, git: {commit: "{{ .GitHash2 }}"}},
				]
			}
		},
	}`

	const initialContent = `package foo

		p := 7`

	h := writeGitRepo(t, filepath.Join(tempDir, "remotegit"), map[string]string{
		"foo.rego": initialContent,
	}, nil)

	h2 := writeGitFiles(t, filepath.Join(tempDir, "remotegit"), map[string]string{
		"foo.rego": `package foo

		p := 8`,
	})

	bs := render(t, tmpl, struct {
		Path              string
		GitHash, GitHash2 string
	}{
		Path:     tempDir,
		GitHash:  h.String(),
		GitHash2: h2.String(),
	})

	report := oneshot(t, bs, tempDir).Report()

	if report.Bundles["test_bundle"].State != service.BuildStateConfigError || report.Bundles["test_bundle"].Message != `requirements on "test_src" (default) conflict` {
		t.Fatal(report)
	}

}

func TestSyncDatasourceHTTP(t *testing.T) {
	payloadContents := `{"data": "data"}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "unexpected request method", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(payloadContents))
		if err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	tempDir := t.TempDir()

	tmpl := `{
		bundles: {
			test_bundle: {
				object_storage: {
					filesystem: {
						path: "{{ printf "%s/%s" .Path "bundles.tar.gz" }}",
					}
				},
				requirements: [
					{source: test_src},
				],
			},
		},
		sources: {
			test_src: {
				directory: "some/path",
				datasources: [
					{
						name: "http_data",
						path: "data",
						type: "http",
						config: {
							url: "{{ .URL }}"
						}
					}
				]
			},
		},
	}`

	bs := render(t, tmpl, struct {
		Path string
		URL  string
		Body string
	}{
		Path: tempDir,
		URL:  ts.URL,
		Body: payloadContents,
	})

	svc := oneshot(t, bs, tempDir)
	report := svc.Report()

	if report.Bundles["test_bundle"].State != service.BuildStateSuccess {
		t.Fatalf("expected bundle to be ready, got: %v", report.Bundles["test_bundle"].State.String())
	}

}

func TestSyncDatasourceHTTP_PostMethodWithBody(t *testing.T) {
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

		if r.Method != "POST" {
			http.Error(w, "unexpected request method", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write([]byte(payloadContents))
		if err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	tempDir := t.TempDir()

	tmpl := `{
		bundles: {
			test_bundle: {
				object_storage: {
					filesystem: {
						path: "{{ printf "%s/%s" .Path "bundles.tar.gz" }}",
					}
				},
				requirements: [
					{source: test_src},
				],
			},
		},
		sources: {
			test_src: {
				directory: "some/path",
				datasources: [
					{
						name: "http_data",
						path: "data",
						type: "http",
						config: {
							url: "{{ .URL }}",
							method: "POST",
							body: '{{ .Body }}',
							headers: {
								"content-type": "application/json"
							}
						}
					}
				]
			},
		},
	}`

	bs := render(t, tmpl, struct {
		Path string
		URL  string
		Body string
	}{
		Path: tempDir,
		URL:  ts.URL,
		Body: payloadContents,
	})

	svc := oneshot(t, bs, tempDir)
	report := svc.Report()

	if report.Bundles["test_bundle"].State != service.BuildStateSuccess {
		t.Fatalf("expected bundle to be ready, got: %v", report.Bundles["test_bundle"].State.String())
	}
}

func TestGitSyncOneShot(t *testing.T) {
	tempDir := t.TempDir()

	tmpl := `{
		bundles: {
			test_bundle: {
				object_storage: {
					filesystem: {
						path: "{{ printf "%s/%s" .Path "bundles.tar.gz" }}",
					}
				},
				requirements: [
					{source: test_src},
				],
			},
		},
		sources: {
			test_src: {
				git: {
					repo: "{{ printf "%s/%s" .Path "remotegit" }}",
					reference: refs/heads/main,
				},
			},
		},
	}`

	const firstContent = `package foo

p := 1`

	const secondContent = `package foo

p := 2`

	remoteGitPath := filepath.Join(tempDir, "remotegit")
	h1 := writeGitRepo(t, remoteGitPath, map[string]string{
		"foo.rego": firstContent,
	}, nil)

	// Create the main branch (writeGitRepo creates master by default)
	repo, err := git.PlainOpen(remoteGitPath)
	if err != nil {
		t.Fatalf("expected no error opening repo: %v", err)
	}

	w, err := repo.Worktree()
	if err != nil {
		t.Fatalf("expected no error getting worktree: %v", err)
	}

	headRef, err := repo.Head()
	if err != nil {
		t.Fatalf("expected no error getting HEAD: %v", err)
	}

	if err := w.Checkout(&git.CheckoutOptions{
		Branch: "refs/heads/main",
		Hash:   headRef.Hash(),
		Create: true,
	}); err != nil {
		t.Fatalf("expected no error creating main branch: %v", err)
	}

	bs := render(t, tmpl, struct {
		Path string
	}{
		Path: tempDir,
	})

	// First one-shot run: Create service, execute, verify first commit
	svc1 := oneshot(t, bs, tempDir)
	report1 := svc1.Report()

	if report1.Bundles["test_bundle"].State != service.BuildStateSuccess {
		t.Fatalf("expected bundle to be ready after first run, got: %v", report1.Bundles["test_bundle"].State.String())
	}

	glob := filepath.Join(tempDir, "data", "*", "sources", "test_src", "repo", "foo.rego")
	matches, err := filepath.Glob(glob)
	if err != nil {
		t.Fatalf("Failed to glob for foo.rego: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("No foo.rego file found matching pattern: %s", glob)
	}

	filePath := matches[0]
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", filePath, err)
	}
	if string(data) != firstContent {
		t.Fatalf("expected first content, got: %s", string(data))
	}

	// Add second commit to remote git repo
	h2 := writeGitFiles(t, filepath.Join(tempDir, "remotegit"), map[string]string{
		"foo.rego": secondContent,
	})

	t.Logf("First commit: %s", h1.String())
	t.Logf("Second commit: %s", h2.String())

	// Second one-shot run: Create NEW service instance, execute, verify second commit
	// This simulates the service restarting
	svc2 := oneshot(t, bs, tempDir)
	report2 := svc2.Report()

	if report2.Bundles["test_bundle"].State != service.BuildStateSuccess {
		t.Fatalf("expected bundle to be ready after second run, got: %v", report2.Bundles["test_bundle"].State.String())
	}

	// Verify the file content was updated to the second commit
	data, err = os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", filePath, err)
	}
	if string(data) != secondContent {
		t.Fatalf("expected second content after git update, got: %s", string(data))
	}
}

func render(t *testing.T, tmpl string, params any) []byte {

	var buf bytes.Buffer
	tpl, err := template.New("config").Parse(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if err := tpl.Execute(&buf, params); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func oneshot(t *testing.T, bs []byte, dir string) *service.Service {

	log := logging.NewLogger(logging.Config{Level: logging.LevelDebug})

	cfg, err := config.Parse(bs)
	if err != nil {
		t.Fatal(err)
	}

	svc := service.New().
		WithConfig(cfg).
		WithPersistenceDir(filepath.Join(dir, "data")).
		WithSingleShot(true).
		WithMigrateDB(true).
		WithLogger(log)

	err = svc.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	return svc
}

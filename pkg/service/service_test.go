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
	"time"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/logging"
	"github.com/open-policy-agent/opa-control-plane/pkg/service"
	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
	"golang.org/x/sync/errgroup"
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

func TestBundleStatusPushSuccess(t *testing.T) {

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
				revision: "{{ .Revision }}",
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
		Path     string
		GitHash  string
		Revision string
	}{
		Path:     tempDir,
		GitHash:  h.String(),
		Revision: "time.now_ns()",
	})

	log := logging.NewLogger(logging.Config{Level: logging.LevelDebug})

	cfg, err := config.Parse(bs)
	if err != nil {
		t.Fatal(err)
	}

	svc := service.New().
		WithConfig(cfg).
		WithPersistenceDir(filepath.Join(tempDir, "data")).
		WithMigrateDB(true).
		WithLogger(log)

	var g errgroup.Group
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	stopped := make(chan struct{})
	g.Go(func() error {
		defer close(stopped)
		return svc.Run(ctx)
	})

	pollCtx, pollCancel := context.WithDeadline(t.Context(), time.Now().Add(10*time.Second))
	defer pollCancel()

	status := awaitBundleStatus(pollCtx, t, svc, "test_bundle")

	cancel()
	<-stopped

	if status.Phase != service.BuildPhasePush.String() {
		t.Fatalf("expected bundle phase %v but got %v", service.BuildPhasePush.String(), status.Phase)
	}

	if status.Status != service.BuildStateSuccess.String() {
		t.Fatalf("expected bundle status %v but got %v", service.BuildStateSuccess.String(), status.Status)
	}
}

func TestBundleStatusPushFailed(t *testing.T) {

	tempDir := t.TempDir()

	tmpl := `{
		bundles: {
			test_bundle: {
				object_storage: {
					aws: {
						bucket: "{{ printf "%s" "no_such_bucket" }}",
                        key: "{{ printf "%s" "no_such_key" }}",
                        region: "{{ printf "%s" "no_such_region" }}",
					}
				},
				requirements: [
					{source: test_src, git: {commit: "{{ .GitHash }}"}},
				],
				revision: "{{ .Revision }}",
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
		Path     string
		GitHash  string
		Revision string
	}{
		Path:     tempDir,
		GitHash:  h.String(),
		Revision: "time.now_ns()",
	})

	log := logging.NewLogger(logging.Config{Level: logging.LevelDebug})

	cfg, err := config.Parse(bs)
	if err != nil {
		t.Fatal(err)
	}

	svc := service.New().
		WithConfig(cfg).
		WithPersistenceDir(filepath.Join(tempDir, "data")).
		WithMigrateDB(true).
		WithLogger(log)

	var g errgroup.Group
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	stopped := make(chan struct{})
	g.Go(func() error {
		defer close(stopped)
		return svc.Run(ctx)
	})

	pollCtx, pollCancel := context.WithDeadline(t.Context(), time.Now().Add(10*time.Second))
	defer pollCancel()

	status := awaitBundleStatus(pollCtx, t, svc, "test_bundle")

	cancel()
	<-stopped

	if status.Phase != service.BuildPhasePush.String() {
		t.Fatalf("expected bundle phase %v but got %v", service.BuildPhasePush.String(), status.Phase)
	}

	if status.Status != service.BuildStatePushFailed.String() {
		t.Fatalf("expected bundle status %v but got %v", service.BuildStatePushFailed.String(), status.Status)
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

	err = svc.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	return svc
}

// mock types for SecretProviderFactory tests

type mockSecretProviderFactory struct {
	calls []string
}

func (f *mockSecretProviderFactory) SecretProviderForTenant(_ context.Context, tenant string) (pkgsync.SecretProvider, error) {
	f.calls = append(f.calls, tenant)
	return &mockSecretProvider{tenant: tenant}, nil
}

type nilSecretProviderFactory struct {
	calls []string
}

func (f *nilSecretProviderFactory) SecretProviderForTenant(_ context.Context, tenant string) (pkgsync.SecretProvider, error) {
	f.calls = append(f.calls, tenant)
	return nil, nil
}

type mockSecretProvider struct {
	tenant string
}

func (p *mockSecretProvider) GetSecret(_ context.Context, name string) (map[string]any, error) {
	return map[string]any{
		"type":  "token_auth",
		"token": fmt.Sprintf("token-for-%s-%s", p.tenant, name),
	}, nil
}

func TestSecretProviderFactoryCalledPerTenant(t *testing.T) {

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
					credentials: my_creds,
					reference: refs/heads/main,
				}
			}
		}
	}`, filepath.Join(t.TempDir(), "bundles"))

	factory := &mockSecretProviderFactory{}

	svc := service.New().
		WithRawConfig(bs).
		WithPersistenceDir(filepath.Join(t.TempDir(), "data")).
		WithSingleShot(true).
		WithMigrateDB(true).
		WithSecretProviderFactory(factory)

	_ = svc.Run(t.Context())

	if len(factory.calls) == 0 {
		t.Fatal("expected SecretProviderFactory to be called")
	}
	if factory.calls[0] != "default" {
		t.Fatalf("expected tenant 'default', got %q", factory.calls[0])
	}
}

func TestSecretProviderFactoryReturningNil(t *testing.T) {

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
					credentials: my_creds,
					reference: refs/heads/main,
				}
			}
		}
	}`, filepath.Join(t.TempDir(), "bundles"))

	factory := &nilSecretProviderFactory{}

	svc := service.New().
		WithRawConfig(bs).
		WithPersistenceDir(filepath.Join(t.TempDir(), "data")).
		WithSingleShot(true).
		WithMigrateDB(true).
		WithSecretProviderFactory(factory)

	_ = svc.Run(t.Context())

	if len(factory.calls) == 0 {
		t.Fatal("expected factory to be consulted")
	}
}

func TestSecretProviderFactoryWithGitSync(t *testing.T) {

	tempDir := t.TempDir()

	repoDir := filepath.Join(tempDir, "remotegit")
	h := writeGitRepo(t, repoDir, map[string]string{
		"foo.rego": "package foo\np := 1",
	}, nil)

	bs := render(t, `{
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
					repo: "{{ .RepoDir }}",
					reference: refs/heads/master,
				},
			},
		},
	}`, struct {
		Path    string
		GitHash string
		RepoDir string
	}{
		Path:    tempDir,
		GitHash: h.String(),
		RepoDir: repoDir,
	})

	factory := &mockSecretProviderFactory{}

	svc := service.New().
		WithRawConfig(bs).
		WithPersistenceDir(filepath.Join(tempDir, "data")).
		WithSingleShot(true).
		WithMigrateDB(true).
		WithSecretProviderFactory(factory)

	if err := svc.Run(t.Context()); err != nil {
		t.Fatal(err)
	}

	report := svc.Report()
	if report.Bundles["test_bundle"].State != service.BuildStateSuccess {
		t.Fatalf("expected success, got %v: %s", report.Bundles["test_bundle"].State, report.Bundles["test_bundle"].Message)
	}

	if len(factory.calls) == 0 {
		t.Fatal("expected factory to be called")
	}

	glob := filepath.Join(tempDir, "data", "*", "sources", "test_src", "repo", "foo.rego")
	matches, err := filepath.Glob(glob)
	if err != nil || len(matches) == 0 {
		t.Fatalf("expected foo.rego to be synced, glob: %s, err: %v", glob, err)
	}

	content, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "package foo\np := 1" {
		t.Fatalf("unexpected content: %s", content)
	}
}

// awaitBundleStatus polls the database until a bundle status record appears
// for the given bundle, or the context expires.
func awaitBundleStatus(ctx context.Context, t *testing.T, svc *service.Service, bundle string) *config.BundleStatus {
	t.Helper()
	for {
		if svc.Ready(ctx) == nil {
			status, err := svc.Database().GetLatestBundleStatus(ctx, "internal", "default", bundle)
			if err == nil && status != nil {
				return status
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("timed out waiting for bundle status")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

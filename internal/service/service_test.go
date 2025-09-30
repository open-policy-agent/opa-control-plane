package service_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"text/template"

	"github.com/styrainc/opa-control-plane/internal/config"
	"github.com/styrainc/opa-control-plane/internal/logging"
	"github.com/styrainc/opa-control-plane/internal/service"
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
					repo: https://example.com/repo.git,  # doesn't matter
					credentials: test_creds,
					reference: refs/heads/main,
				}
			}
		},
		secrets: {
			test_creds: {}  # not configured
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

	foo, err := os.ReadFile(filepath.Join(tempDir, "data", "8d72363cb5de6ec0608d85a601a02e4c", "sources", "test_src", "repo", "foo.rego"))
	if err != nil {
		t.Fatal(err)
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

	if report.Bundles["test_bundle"].State != service.BuildStateConfigError || report.Bundles["test_bundle"].Message != `requirements on "test_src" conflict` {
		t.Fatal(report)
	}

}

func render(t *testing.T, tmpl string, params interface{}) []byte {

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

	cfg, err := config.Parse(bytes.NewBuffer(bs))
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

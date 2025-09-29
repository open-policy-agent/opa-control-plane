package service_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"text/template"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/open-policy-agent/opa/ast"    // nolint:staticcheck
	"github.com/open-policy-agent/opa/bundle" // nolint:staticcheck
	"github.com/styrainc/opa-control-plane/internal/config"
	"github.com/styrainc/opa-control-plane/internal/logging"
	"github.com/styrainc/opa-control-plane/internal/service"
	"github.com/styrainc/opa-control-plane/internal/test/libraries"
	"github.com/styrainc/opa-control-plane/internal/test/tempfs"
	"github.com/styrainc/opa-control-plane/internal/util"
	"gopkg.in/yaml.v3"
)

// TestCases is a struct that holds a slice of test cases in a YAML file.
type TestCases struct {
	Cases []TestCase `yaml:"cases"`
}

type TestCase struct {
	Note               string            `yaml:"note"`
	Config             string            `yaml:"config"`
	ContentParameters  map[string]string `yaml:"content_parameters"`
	GitFiles           map[string]string `yaml:"git_files"`
	HTTPEndpoints      map[string]string `yaml:"http_endpoints"`
	ExpectedFilesystem []string          `yaml:"expected_filesystem"`
	ExpectedBundle     ExpectedBundle    `yaml:"expected_bundle"`
}

type ExpectedBundle struct {
	Rego map[string]string `yaml:"rego"`
	Data string            `yaml:"data"`
}

func TestService(t *testing.T) {

	// Set mock AWS credentials to avoid IMDS errors.
	t.Setenv("AWS_ACCESS_KEY_ID", "mock-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "mock-secret-key")
	t.Setenv("AWS_REGION", "us-east-1")

	for _, test := range loadTestCases(t).Cases {
		t.Run(test.Note, func(t *testing.T) {

			tempfs.WithTempFS(t, nil, func(t *testing.T, rootDir string) {

				t.Log("Root Directory:", rootDir)

				// Create a mock S3 service with a test bucket and a mock HTTP endpoints to serve the datasource(s).

				for name, content := range test.HTTPEndpoints {
					test.HTTPEndpoints[name] = formatTemplate(t, content, test.ContentParameters)
				}

				mock, s3TS := testS3Service(t, "test")
				httpTS := testHTTPDataServer(t, test.HTTPEndpoints)

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				// Setup the filesystem for the test case. Unfortunately, we can't do it with
				// TempFS as we need the remote git dir to emit the files.

				configPath := path.Join(rootDir, "config.yaml")
				persistenceDir := path.Join(rootDir, "data")
				remoteGitDir := path.Join(rootDir, "remote-git")

				maps.Copy(test.ContentParameters, map[string]string{
					"git_url":  remoteGitDir,
					"s3_url":   s3TS.URL,
					"http_url": httpTS.URL,
				})

				cfg := formatTemplate(t, test.Config, test.ContentParameters)
				writeFile(t, configPath, cfg)
				writeGitRepo(t, remoteGitDir, test.GitFiles, test.ContentParameters)

				root, err := config.Parse(strings.NewReader(cfg))
				if err != nil {
					t.Fatal(err)
				}

				// Run the service with the config file and persistence dir and expect bundle to have been written to S3
				svc := service.New().
					WithConfig(root).
					WithPersistenceDir(persistenceDir).
					WithBuiltinFS(util.NewEscapeFS(libraries.FS)).
					WithSingleShot(true).
					WithMigrateDB(true).
					WithLogger(logging.NewLogger(logging.Config{Level: logging.LevelDebug}))
				if err := svc.Init(ctx); err != nil {
					t.Fatal(err)
				}
				if err := svc.Run(ctx); err != nil {
					t.Fatal(err)
				}

				obj, err := mock.GetObject("test", "bundle.tar.gz", nil)
				if obj == nil || err != nil {
					t.Fatal(err)
				}

				// Once the bundle was downloaded from S3, check the filesystem layout the service used to
				// construct the bundle. Filter out the git hidden directories and database file constructed.

				var files []string
				err = filepath.Walk(persistenceDir, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if info.IsDir() {
						return nil
					}

					path = strings.TrimPrefix(path, persistenceDir)

					switch slashPath := filepath.ToSlash(path); {
					case strings.Contains(slashPath, "/.git/"):
					case slashPath == "/sqlite.db":
					default:
						files = append(files, path)
					}

					return nil
				})
				if err != nil {
					t.Fatal(err)
				}

				if !reflect.DeepEqual(files, test.ExpectedFilesystem) {
					t.Fatalf("expected files on disk: %v, got: %v", test.ExpectedFilesystem, files)
				}

				// Filesystem layout used to construct the bundle matches the expectations, so check the
				// actual bundle contents - both Rego and JSON contents.

				b, err := bundle.NewReader(obj.Contents).Read()
				if err != nil {
					t.Fatal(err)
				}

				if len(test.ExpectedBundle.Rego) != len(b.Modules) {
					t.Fatalf("expected %v modules but got %v", len(test.ExpectedBundle.Rego), len(b.Modules))
				}

				got := map[string]*ast.Module{}
				for _, mf := range b.Modules {
					p := strings.TrimPrefix(mf.Path, "/")
					got[p] = mf.Parsed
					t.Log("got", p)
				}

				for k := range test.ExpectedBundle.Rego {
					rego := formatTemplate(t, test.ExpectedBundle.Rego[k], test.ContentParameters)
					module, err := ast.ParseModule(k, rego)
					if err != nil {
						t.Fatalf("failed to parse rego module %q: %v", k, err)
					}

					if got[k] == nil {
						t.Fatalf("expected module %q to be present in bundle but got nil", k)
					}

					if !module.Equal(got[k]) {
						t.Fatalf("exp:\n%v\n\ngot:\n%v", module.String(), got[k].String())
					}
				}

				var expectedData interface{}

				if test.ExpectedBundle.Data != "" {
					data := formatTemplate(t, test.ExpectedBundle.Data, test.ContentParameters)

					if err := json.Unmarshal([]byte(data), &expectedData); err != nil {
						t.Fatalf("failed to unmarshal expected data: %v", err)
					}
				} else {
					expectedData = map[string]interface{}{}
				}

				if !reflect.DeepEqual(b.Data, expectedData) {
					t.Fatalf("expected data to be %v but got %v", expectedData, b.Data)
				}

				// Shutdown the service and wait for it to finish.

				cancel()
			})
		})
	}
}

func formatTemplate(t *testing.T, templateStr string, contentParameters map[string]string) string {
	buf := bytes.NewBuffer(nil)
	parameters := map[string]interface{}{}
	for k, v := range contentParameters {
		parameters[k] = v
	}

	funcs := template.FuncMap{
		"base64encode": func(s string) (string, error) {
			return base64.StdEncoding.EncodeToString([]byte(s)), nil
		},
	}

	tmpl, err := template.New("data").Funcs(funcs).Parse(templateStr)
	if err != nil {
		t.Fatal(err)
	}

	err = tmpl.Execute(buf, parameters)
	if err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func loadTestCases(t *testing.T) TestCases {
	var testCases TestCases

	err := filepath.Walk("testdata/", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var cases TestCases
		err = yaml.Unmarshal(data, &cases)
		if err != nil {
			return err
		}

		testCases.Cases = append(testCases.Cases, cases.Cases...)
		return nil

	})

	if err != nil {
		t.Fatal(err)
	}

	return testCases
}

func testS3Service(t *testing.T, bucket string) (*s3mem.Backend, *httptest.Server) {
	mock := s3mem.New()
	_ = mock.CreateBucket(bucket)
	ts := httptest.NewServer(gofakes3.New(mock).Server())
	t.Cleanup(ts.Close)
	return mock, ts
}

func testHTTPDataServer(t *testing.T, files map[string]string) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		content, ok := files[r.URL.Path]
		if !ok {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}

		_, err := w.Write([]byte(content))
		if err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func writeFile(t *testing.T, path string, content string) {
	if err := os.MkdirAll(filepath.Dir(path), 0777); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func writeGitRepo(t *testing.T, remoteGitDir string, files map[string]string, parameters map[string]string) plumbing.Hash {
	for path, content := range files {
		writeFile(t, filepath.Join(remoteGitDir, path), formatTemplate(t, content, parameters))
	}

	if len(files) > 0 {
		repo, err := git.PlainInit(remoteGitDir, false)
		if err != nil {
			t.Fatal(err)
		}

		w, err := repo.Worktree()
		if err != nil {
			t.Fatal(err)
		}

		for name := range files {
			if _, err := w.Add(name); err != nil {
				t.Fatal(err)
			}
		}

		if h, err := w.Commit("Initial commit", &git.CommitOptions{Author: &object.Signature{}}); err != nil {
			t.Fatal(err)
		} else {
			return h
		}
	}

	var zero plumbing.Hash
	return zero
}

func writeGitFiles(t *testing.T, gitDir string, files map[string]string) plumbing.Hash {
	for path, content := range files {
		writeFile(t, filepath.Join(gitDir, path), content)
	}

	if len(files) > 0 {
		repo, err := git.PlainOpen(gitDir)
		if err != nil {
			t.Fatal(err)
		}
		w, err := repo.Worktree()
		if err != nil {
			t.Fatal(err)
		}
		for name := range files {
			if _, err := w.Add(name); err != nil {
				t.Fatal(err)
			}
		}
		if h, err := w.Commit("msg", &git.CommitOptions{Author: &object.Signature{}}); err != nil {
			t.Fatal(err)
		} else {
			return h
		}
	}

	var zero plumbing.Hash
	return zero
}

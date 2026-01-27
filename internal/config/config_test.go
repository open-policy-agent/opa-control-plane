package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/google/go-cmp/cmp"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
)

func TestParseSecretResolve(t *testing.T) {

	result, err := config.Parse([]byte(`{
		sources: {
			foo: {
				git: {
					repo: https://example.com/repo.git,
					credentials: secret1
				},
			}
		},
		secrets: {
			secret1: {
				type: basic_auth,
				username: bob,
				password: '${OPACTL_PASSWORD}'
			}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("OPACTL_PASSWORD", "passw0rd")

	value, err := result.Sources["foo"].Git.Credentials.Resolve(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	exp := &config.SecretBasicAuth{
		Username: "bob",
		Password: "passw0rd",
	}

	if !reflect.DeepEqual(value, exp) {
		t.Fatalf("expected: %v\n\ngot: %v", exp, value)
	}
}

func TestFilesMarshallingRoundtrip(t *testing.T) {

	cfg, err := config.Parse([]byte(`{
		bundles: {
			foo: {
				excluded_files: ["bar.rego","*.json"],
				requirements: [{source: foo}]
			}
		},
		sources: {
			foo: {
				files: {
					"foo.rego": "cGFja2FnZSBmb28=",
				},
			}
		},
		stacks: {
			bar: {
				selector: {
					labelX: [abcd]
				}
			}
		},
		tokens: {
			admin: {
				api_key: x1234,
				scopes: [
					{role: administrator}
				]
			}
		}
	}`))

	if err != nil {
		t.Fatal(err)
	}

	if files, _ := cfg.Sources["foo"].Files(); files["foo.rego"] != "package foo" {
		t.Fatalf("expected file to be 'package foo' but got:\n%v", files["foo.rego"])
	}

	bs, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cfg2, err := config.Parse(bs)
	if err != nil {
		t.Fatal(err)
	}

	if !cfg.Bundles["foo"].Equal(cfg2.Bundles["foo"]) {
		t.Fatal("expected bundles to be equal")
	}

	if !cfg.Stacks["bar"].Equal(cfg2.Stacks["bar"]) {
		t.Fatal("expected stacks to be equal")
	}

	if !cfg.Tokens["admin"].Equal(cfg2.Tokens["admin"]) {
		t.Fatal("expected tokens to be equal")
	}

}

func TestSelectorMatch(t *testing.T) {
	cases := []struct {
		labels   string
		selector string
		exp      bool
	}{
		{
			labels:   `{foo: bar}`,
			selector: `{foo: []}`,
			exp:      true,
		},
		{
			labels:   `{foo: bar}`,
			selector: `{foo: [bar]}`,
			exp:      true,
		},
		{
			labels:   `{foo: bar}`,
			selector: `{foo: [baz, bar]}`,
			exp:      true,
		},
		{
			labels:   `{foo: bar, baz: qux}`,
			selector: `{foo: [baz, bar], baz: [qux]}`,
			exp:      true,
		},
		{
			labels:   `{foo: bar, baz: qux}`,
			selector: `{foo: [baz, bar], qux: [corge]}`,
			exp:      false,
		},
		{
			labels:   `{foo: bar, baz: qux}`,
			selector: `{foo: [bar], "do-not-match": [], baz: [qux]}`,
			exp:      false,
		},
		{
			labels:   `{foo: bar}`,
			selector: `{foo: [ba*]}`,
			exp:      true,
		},
	}

	for _, tc := range cases {
		labels := config.Labels{}
		selector := config.Selector{}
		if err := yaml.Unmarshal([]byte(tc.labels), &labels); err != nil {
			t.Fatal(err)
		}
		if err := yaml.Unmarshal([]byte(tc.selector), &selector); err != nil {
			t.Fatal(err)
		}
		match := selector.Matches(labels)
		if tc.exp {
			if !match {
				t.Fatalf("expected match for selector %v and labels %v", selector, labels)
			}
		} else if match {
			t.Fatalf("expected no match for selector %v and labels %v", selector, labels)
		}
	}
}

func TestValidateRoleEnum(t *testing.T) {

	_, err := config.Parse([]byte(`{
		tokens: {
			admin: {
				api_key: x1234,
				scopes: [
					{role: xxxadministrator}
				]
			}
		}
	}`))
	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), "value must be one of 'administrator', 'viewer', 'owner', 'stack_owner'") {
		t.Fatalf("unexpected error: %v", err)
	}

}

func TestTopoSortSources(t *testing.T) {

	config, err := config.Parse([]byte(`{
		sources: {
			A: {
				requirements: [{source: B}]
			},
			B: {
				requirements: [{source: C}, {source: D}]
			},
			C: {
				requirements: [{source: nonexistent}]
			},
			D: {
				requirements: [{source: C}]
			}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}

	sorted, err := config.TopologicalSortedSources()
	if err != nil {
		t.Fatal(err)
	}

	exp := []string{"C", "D", "B", "A"}
	if len(sorted) != len(exp) {
		t.Fatal("unexpected number of sources")
	}

	for i := range exp {
		if exp[i] != sorted[i].Name {
			t.Fatalf("expected %v but got %v", exp, sorted)
		}
	}

}

func TestTopoSortSourcesCycle(t *testing.T) {

	config, err := config.Parse([]byte(`{
		sources: {
			A: {
				requirements: [{source: B}]
			},
			B: {
				requirements: [{source: C}, {source: D}]
			},
			C: {
				requirements: [{source: E}]
			},
			D: {
				requirements: [{source: C}]
			},
			E: {
				requirements: [{source: A}]
			}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}

	_, err = config.TopologicalSortedSources()
	if err == nil || err.Error() != "cycle found on source \"A\"" {
		t.Fatal("expected cycle error on source A but got:", err)
	}

}

func TestSetSQLitePersistentByDefault(t *testing.T) {
	for _, tc := range []struct {
		note      string
		input     *config.Root
		exp       *config.Root
		expSQLite bool
	}{
		{
			note:  "no database whatsoever",
			input: &config.Root{},
			exp: &config.Root{Database: &config.Database{
				SQL: &config.SQLDatabase{
					Driver: "sqlite3",
					DSN:    "/tmp/sqlite.db",
				},
			}},
			expSQLite: true,
		},
		{
			note: "existing non-sqlite SQL database",
			input: &config.Root{Database: &config.Database{
				SQL: &config.SQLDatabase{
					Driver: "postgresql",
					DSN:    "postgresql://foo:bar@localhost:5432/opactl",
				},
			}},
			exp: &config.Root{Database: &config.Database{
				SQL: &config.SQLDatabase{
					Driver: "postgresql",
					DSN:    "postgresql://foo:bar@localhost:5432/opactl",
				},
			}},
			expSQLite: false,
		},
		{
			note: "existing AWSRDS database",
			input: &config.Root{Database: &config.Database{
				AWSRDS: &config.AmazonRDS{
					Driver: "mysql",
					DSN:    "mysql://foo:bar@localhost:5432/opactl",
				},
			}},
			exp: &config.Root{Database: &config.Database{
				AWSRDS: &config.AmazonRDS{
					Driver: "mysql",
					DSN:    "mysql://foo:bar@localhost:5432/opactl",
				},
			}},
			expSQLite: false,
		},
	} {
		t.Run(tc.note, func(t *testing.T) {
			p := "/tmp"
			isSQLite := tc.input.SetSQLitePersistentByDefault(p)
			if diff := cmp.Diff(tc.exp, tc.input); diff != "" {
				t.Error("unexpected diff, (-want, +got)", diff)
			}
			if isSQLite != tc.expSQLite {
				t.Errorf("unexpected return value, want %v, got %v", tc.expSQLite, isSQLite)
			}
		})
	}
}

func TestServiceApiPrefixValidation(t *testing.T) {
	tests := []struct {
		note      string
		config    string
		shouldErr bool
		errMsg    string
	}{
		{
			note: "valid api_prefix with leading slash",
			config: `{
		service: {
			api_prefix: "/api/v1"
		}
	}`,
			shouldErr: false,
		},
		{
			note: "valid api_prefix with just slash",
			config: `{
		service: {
			api_prefix: "/"
		}
	}`,
			shouldErr: false,
		},
		{
			note: "invalid api_prefix without leading slash",
			config: `{
		service: {
			api_prefix: "api/v1"
		}
	}`,
			shouldErr: true,
			errMsg:    "does not match pattern",
		},
		{
			note: "valid when api_prefix omitted completely",
			config: `{
		service: {}
	}`,
			shouldErr: false,
		},
		{
			note: "invalid api_prefix with trailing slash",
			config: `{
		service: {
			api_prefix: "/api/v1/"
		}
	}`,
			shouldErr: true,
			errMsg:    "does not match pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.note, func(t *testing.T) {
			_, err := config.Parse([]byte(tt.config))
			if tt.shouldErr {
				if err == nil {
					t.Fatalf("expected validation error but got none")
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Fatalf("expected error containing %q but got: %v", tt.errMsg, err)
				}
			} else if err != nil {
				t.Fatalf("expected no error but got: %v", err)
			}
		})
	}
}

func TestValidateYAML(t *testing.T) {
	{ // This is OK, empty sources can be used for PUT /sources/<name>/data/<path> updates
		cfg := []byte(`
sources:
  empty-source:
`)
		_, err := config.Parse(cfg)
		if err != nil {
			t.Fatal(err)
		}
	}
	{ // These cannot be empty: It won't panic, but it won't pass validation either
		cfg := []byte(`
tokens:
  empty-token:
bundles:
  empty-bundle:
secrets:
  empty-secret:
stacks:
  empty-stack:
`)
		_, err := config.Parse(cfg)
		exp := []string{
			`- at '/stacks/empty-stack': got null, want object`,
			`- at '/tokens/empty-token': got null, want object`,
			`- at '/bundles/empty-bundle': got null, want object`,
			`- at '/secrets/empty-secret': got null, want object`,
		}
		for _, line := range exp {
			if !strings.Contains(err.Error(), line) {
				t.Errorf("expected error with line %q", line)
			}
		}
		if t.Failed() && err != nil {
			t.Logf("error: %q", err.Error())
		}
	}
}

func TestRequirementsEqual(t *testing.T) {
	reqs := func(r ...config.Requirement) config.Requirements { return r }
	a0, b0 := "source-a", "source-b"
	for _, tc := range []struct {
		name string
		a, b config.Requirements
		exp  bool
	}{
		{
			name: "simple equal",
			a:    reqs(config.Requirement{Source: &a0}, config.Requirement{Source: &b0}),
			b:    reqs(config.Requirement{Source: &a0}, config.Requirement{Source: &b0}),
			exp:  true,
		},
		{
			name: "simple unequal",
			a:    reqs(config.Requirement{Source: &a0}, config.Requirement{Source: &b0}),
			b:    reqs(config.Requirement{Source: &a0}, config.Requirement{Source: &a0}),
		},
		{
			name: "path unequal",
			a:    reqs(config.Requirement{Source: &a0, Path: "p0"}, config.Requirement{Source: &b0}),
			b:    reqs(config.Requirement{Source: &a0}, config.Requirement{Source: &b0}),
		},
		{
			name: "with path+prefix equal",
			a:    reqs(config.Requirement{Source: &a0, Path: "p0", Prefix: "p01"}, config.Requirement{Source: &a0}),
			b:    reqs(config.Requirement{Source: &a0}, config.Requirement{Source: &a0, Path: "p0", Prefix: "p01"}),
			exp:  true,
		},
		{
			name: "with path equal",
			a:    reqs(config.Requirement{Source: &a0, Path: "p0"}, config.Requirement{Source: &a0}),
			b:    reqs(config.Requirement{Source: &a0}, config.Requirement{Source: &a0, Path: "p0"}),
			exp:  true,
		},
		{
			name: "with prefix equal",
			a:    reqs(config.Requirement{Source: &a0, Prefix: "p0"}, config.Requirement{Source: &a0}),
			b:    reqs(config.Requirement{Source: &a0}, config.Requirement{Source: &a0, Prefix: "p0"}),
			exp:  true,
		},
		{
			name: "prefix unequal",
			a:    reqs(config.Requirement{Source: &a0, Path: "p0"}, config.Requirement{Source: &a0}),
			b:    reqs(config.Requirement{Source: &a0, Path: "p0"}, config.Requirement{Source: &a0, Prefix: "p1"}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if act := tc.a.Equal(tc.b); act != tc.exp {
				t.Errorf("expected %v, got %v", tc.exp, act)
			}
		})
	}
}

func TestBundleOptionsTargetParsing(t *testing.T) {
	tests := []struct {
		name     string
		config   string
		expected string
		hasError bool
	}{
		{
			name: "default target (empty string defaults to rego)",
			config: `{
				bundles: {
					test: {
						options: {}
					}
				}
			}`,
			expected: "",
		},
		{
			name: "explicit rego target",
			config: `{
				bundles: {
					test: {
						options: {
							target: "rego"
						}
					}
				}
			}`,
			expected: "rego",
		},
		{
			name: "ir target",
			config: `{
				bundles: {
					test: {
						options: {
							target: "ir"
						}
					}
				}
			}`,
			expected: "ir",
		},
		{
			name: "wasm target",
			config: `{
				bundles: {
					test: {
						options: {
							target: "wasm"
						}
					}
				}
			}`,
			expected: "wasm",
		},
		{
			name: "invalid target",
			config: `{
				bundles: {
					test: {
						options: {
							target: "invalid"
						}
					}
				}
			}`,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.Parse([]byte(tt.config))
			if tt.hasError {
				if err == nil {
					t.Fatalf("Expected error for invalid target")
				}
				if !strings.Contains(err.Error(), "value must be one of 'rego', 'ir', 'plan', 'wasm'") {
					t.Errorf("Expected error to contain schema validation message, got %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			bundle := cfg.Bundles["test"]
			if bundle == nil {
				t.Fatal("Expected bundle 'test' to exist")
			}

			if bundle.Options.Target != tt.expected {
				t.Errorf("Expected target %q, got %q", tt.expected, bundle.Options.Target)
			}
		})
	}
}

func TestSourceFilesWithGlobs(t *testing.T) {
	tests := []struct {
		name       string
		setupFiles map[string]string // path -> content
		paths      []string
		expected   map[string]string
		errorMsg   string
	}{
		{
			name: "literal file path",
			setupFiles: map[string]string{
				"foo.rego": "package foo",
			},
			paths: []string{"foo.rego"},
			expected: map[string]string{
				"foo.rego": "package foo",
			},
		},
		{
			name: "simple glob pattern",
			setupFiles: map[string]string{
				"foo.rego": "package foo",
				"bar.rego": "package bar",
				"baz.json": `{"data": "value"}`,
			},
			paths: []string{"*.rego"},
			expected: map[string]string{
				"foo.rego": "package foo",
				"bar.rego": "package bar",
			},
		},
		{
			name: "recursive glob pattern",
			setupFiles: map[string]string{
				"foo.rego":             "package foo",
				"subdir/bar.rego":      "package bar",
				"subdir/deep/baz.rego": "package baz",
			},
			paths: []string{"**/*.rego"},
			expected: map[string]string{
				"subdir/bar.rego":      "package bar",
				"subdir/deep/baz.rego": "package baz",
			},
		},
		{
			name: "match all rego files including root",
			setupFiles: map[string]string{
				"foo.rego":             "package foo",
				"subdir/bar.rego":      "package bar",
				"subdir/deep/baz.rego": "package baz",
			},
			paths: []string{"*.rego", "**/*.rego"},
			expected: map[string]string{
				"foo.rego":             "package foo",
				"subdir/bar.rego":      "package bar",
				"subdir/deep/baz.rego": "package baz",
			},
		},
		{
			name: "multiple patterns",
			setupFiles: map[string]string{
				"foo.rego":        "package foo",
				"data/data.json":  `{"data": "value"}`,
				"other/other.txt": "text",
			},
			paths: []string{"*.rego", "data/*.json"},
			expected: map[string]string{
				"foo.rego":       "package foo",
				"data/data.json": `{"data": "value"}`,
			},
		},
		{
			name: "directory glob",
			setupFiles: map[string]string{
				"dir1/file.rego": "package dir1",
				"dir2/file.rego": "package dir2",
			},
			paths: []string{"dir*/file.rego"},
			expected: map[string]string{
				"dir1/file.rego": "package dir1",
				"dir2/file.rego": "package dir2",
			},
		},
		{
			name: "no matches error",
			setupFiles: map[string]string{
				"foo.txt": "text",
			},
			paths:    []string{"*.rego"},
			errorMsg: "no files matched patterns",
		},
		{
			name:       "file does not exist error",
			setupFiles: map[string]string{},
			paths:      []string{"nonexistent.rego"},
			errorMsg:   "no files matched patterns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			for path, content := range tt.setupFiles {
				fullPath := filepath.Join(tempDir, path)
				dir := filepath.Dir(fullPath)
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatalf("Failed to create directory: %v", err)
				}
				if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to write file: %v", err)
				}
			}

			source := &config.Source{
				Name:      "test",
				Directory: tempDir,
				Paths:     tt.paths,
			}

			files, err := source.Files()

			if tt.errorMsg != "" {
				if err == nil {
					t.Fatalf("Expected error but got none")
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Fatalf("Expected error containing %q but got: %v", tt.errorMsg, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(files) != len(tt.expected) {
				t.Fatalf("Expected %d files, got %d: %v", len(tt.expected), len(files), files)
			}

			for path, expectedContent := range tt.expected {
				actualContent, ok := files[path]
				if !ok {
					t.Errorf("Expected file %q not found in results", path)
					continue
				}
				if actualContent != expectedContent {
					t.Errorf("File %q: expected content %q, got %q", path, expectedContent, actualContent)
				}
			}
		})
	}
}

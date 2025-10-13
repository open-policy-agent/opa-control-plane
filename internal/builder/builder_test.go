package builder_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/opa/ast"    // nolint:staticcheck
	"github.com/open-policy-agent/opa/bundle" // nolint:staticcheck

	"github.com/open-policy-agent/opa-control-plane/internal/builder"
	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/test/tempfs"
)

func TestBuilder(t *testing.T) {

	type mount struct {
		prefix, sub string
	}
	type reqMock struct {
		name   string
		mounts []mount
	}

	type sourceMock struct {
		name          string
		files         map[string]string
		requirements  []reqMock
		includedFiles []string
		excludedFiles []string
	}

	cases := []struct {
		note     string
		sources  []sourceMock
		excluded []string
		exp      map[string]string
		expRoots []string
		expError error
	}{
		{
			note: "no requirements",
			sources: []sourceMock{
				{
					name: "src",
					files: map[string]string{
						"/x/x.rego": `package x
						p := 7`,
						"/x/y/data.json": `{"A": 7}`,
						"/x/z/data.json": `{"B": 7}`,
					},
				},
			},
			excluded: []string{"x/z/data.json"},
			exp: map[string]string{
				"/src/x/x.rego": `package x
				p := 7`,
				"/data.json": `{"x":{"y":{"A":7}}}`,
			},
			expRoots: []string{"x"},
		},
		{
			note: "no requirements, no source name",
			sources: []sourceMock{
				{
					files: map[string]string{
						"/x/x.rego": `package x
						p := 7`,
						"/x/y/data.json": `{"A": 7}`,
						"/x/z/data.json": `{"B": 7}`,
					},
				},
			},
			excluded: []string{"x/z/data.json"},
			exp: map[string]string{
				"/0/x/x.rego": `package x
				p := 7`,
				"/data.json": `{"x":{"y":{"A":7}}}`,
			},
			expRoots: []string{"x"},
		},
		{
			note: "multiple requirements",
			sources: []sourceMock{
				{
					name: "src",
					files: map[string]string{
						"/x/x.rego": `package x
						import rego.v1
						p if data.lib1.q`,
					},
					requirements: []reqMock{{name: "lib1"}},
				},
				{
					name: "lib1",
					files: map[string]string{
						"/lib1.rego": `package lib1
						import rego.v1
						q if data.lib2.r`,
					},
					requirements: []reqMock{{name: "lib2"}},
				},
				{
					name: "lib2",
					files: map[string]string{
						"/lib2.rego": `package lib2
						import rego.v1
						r if input.x > 7`,
					},
				},
				{
					// this source should not show up
					name: "lib3",
					files: map[string]string{
						"/lib3.rego": `package lib3`,
					},
				},
			},
			exp: map[string]string{
				"/src/x/x.rego": `package x
				import rego.v1
				p if data.lib1.q`,
				"/lib1/lib1.rego": `package lib1
				import rego.v1
				q if data.lib2.r`,
				"/lib2/lib2.rego": `package lib2
				import rego.v1
				r if input.x > 7`,
			},
			expRoots: []string{"x", "lib1", "lib2"},
		},
		{
			note: "package conflict: same",
			sources: []sourceMock{
				{
					name: "system",
					files: map[string]string{
						"x.rego": `package x
						p := data.lib1.q`,
					},
					requirements: []reqMock{{name: "lib1"}},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1
						p := data.lib1.q`,
					},
					requirements: []reqMock{{name: "lib2"}},
				},
				{
					name: "lib2",
					files: map[string]string{
						"lib2.rego": `package lib2
						q := 7`,
						// add another file that generates a conflict error
						"lib2_other.rego": `package x

						r := 7`,
					},
				},
			},
			expError: errors.New("requirement \"lib2\" contains conflicting package x\n- package x from \"system\""),
		},
		{
			note: "package conflict: prefix (fixed via separate mounts)",
			sources: []sourceMock{
				{
					name: "system",
					files: map[string]string{
						"x.rego": `package x
						p := data.imported_lib1.q`, // NB: This isn't rewritten! It needs to what we rewrite its requirements to.
					},
					requirements: []reqMock{
						{
							name: "lib1",
							mounts: []mount{
								{sub: "data.lib1", prefix: "data.imported_lib1"},
								{sub: "data.lib2", prefix: "data.imported_lib2"},
								{sub: "data.x", prefix: "data.imported.x"},
							},
						},
					},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1
						p := data.lib1.q
						r := data.lib2.r`,
					},
					requirements: []reqMock{{name: "lib2"}},
				},
				{
					name: "lib2",
					files: map[string]string{
						"lib2.rego": `package lib2
						q := 7`,
						"lib2_other.rego": `package x.y.z
						r := 7`,
						"/x/y/data.json": `{"A": 7}`,
						"/x/z/data.json": `{"A": 8}`,
					},
				},
			},
			excluded: []string{"x/z/data.json"},
			exp: map[string]string{
				"/system/x.rego": `package x
				p := data.imported_lib1.q`,
				"/lib1/lib1.rego": `package imported_lib1
				p := data.imported_lib1.q
				r := data.imported_lib2.r`,
				"/lib2/lib2.rego": `package imported_lib2
				q := 7`,
				"/lib2/lib2_other.rego": `package imported.x.y.z
				r := 7`,
				"/data.json": `{"imported":{"x":{"y":{"A":7}}}}`,
			},
			expRoots: []string{"imported_lib1", "imported_lib2", "imported/x/y", "x"},
		},
		{
			note: "mounts: transitive data moves",
			sources: []sourceMock{
				{
					name: "system",
					requirements: []reqMock{
						{
							name: "lib1",
							mounts: []mount{
								{sub: "data.X", prefix: "data.Y"}, // data.X.a.b.c -> data.Y.a.b.c
							},
						},
					},
				},
				{
					name: "lib1",
					requirements: []reqMock{
						{
							name: "lib2",
							mounts: []mount{
								{sub: "data", prefix: "data.X"}, // data.a.b.c -> data.X.a.b.c
							},
						},
					},
				},
				{
					name: "lib2",
					files: map[string]string{
						"a/b/c/data.json": `{":)":"(:"}`,
					},
				},
			},
			exp: map[string]string{
				"/data.json": `{"Y":{"a":{"b":{"c":{":)":"(:"}}}}}`,
			},
			expRoots: []string{"Y/a/b/c"},
		},
		{
			note: "package conflict: prefix (fixed via single mount)",
			sources: []sourceMock{
				{
					name: "system",
					files: map[string]string{
						"x.rego": `package x
						p := data.imported.lib1.q`, // NB: This isn't rewritten! It needs to what we rewrite its requirements to.
					},
					requirements: []reqMock{
						{
							name: "lib1",
							mounts: []mount{
								{sub: "data", prefix: "data.imported"},
							},
						},
					},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1
						p := data.lib1.q
						r := data.lib2.r`,
					},
					requirements: []reqMock{{name: "lib2"}},
				},
				{
					name: "lib2",
					files: map[string]string{
						"lib2.rego": `package lib2
						q := 7`,
						"lib2_other.rego": `package x.y.z
						r := 7`,
						"/x/y/data.json": `{"A": 7}`,
						"/x/z/data.json": `{"A": 8}`,
					},
				},
			},
			excluded: []string{"x/z/data.json"},
			exp: map[string]string{
				"/system/x.rego": `package x
				p := data.imported.lib1.q`,
				"/lib1/lib1.rego": `package imported.lib1
				p := data.imported.lib1.q
				r := data.imported.lib2.r`,
				"/lib2/lib2.rego": `package imported.lib2
				q := 7`,
				"/lib2/lib2_other.rego": `package imported.x.y.z
				r := 7`,
				"/data.json": `{"imported":{"x":{"y":{"A":7}}}}`,
			},
			expRoots: []string{"imported/lib1", "imported/lib2", "imported/x/y", "x"},
		},
		{
			note: "requirements mounts: processing source twice with different mounts",
			sources: []sourceMock{
				{
					name: "system",
					files: map[string]string{
						"x.rego": `package x
						p := data.imported.lib1.q`, // NB: This isn't rewritten! It needs to what we rewrite its requirements to.
					},
					requirements: []reqMock{
						{
							name: "lib1",
							mounts: []mount{
								{sub: "data", prefix: "data.imported"},
							},
						},
					},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1
						p := data.lib1.q
						r := data.abc.lib2.r`, // matches mount below
					},
					requirements: []reqMock{
						{
							name: "lib2",
							mounts: []mount{
								{sub: "data", prefix: "data.abc"},
							},
						},
					},
				},
				{
					name: "lib2",
					files: map[string]string{
						"lib2.rego": `package lib2
						q := 7`,
					},
				},
			},
			excluded: []string{"x/z/data.json"},
			exp: map[string]string{
				"/system/x.rego": `package x
				p := data.imported.lib1.q`,
				"/lib1/lib1.rego": ` package imported.lib1
		        p := data.imported.lib1.q
		        r := data.imported.abc.lib2.r`,
				"/lib2/lib2.rego": `package imported.abc.lib2
				q := 7`,
			},
			expRoots: []string{"imported/abc/lib2", "imported/lib1", "x"},
		},
		{
			note: "requirements mounts: prefix only",
			sources: []sourceMock{
				{
					name: "system",
					files: map[string]string{
						"x.rego": `package x
						p := data.imported.lib1.q`,
					},
					requirements: []reqMock{
						{
							name: "lib1",
							mounts: []mount{
								{prefix: "data.imported"},
							},
						},
					},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1
						p := true`,
					},
				},
			},
			excluded: []string{"x/z/data.json"},
			exp: map[string]string{
				"/system/x.rego": `package x
				p := data.imported.lib1.q`,
				"/lib1/lib1.rego": ` package imported.lib1
		        p := true`,
			},
			expRoots: []string{"imported/lib1", "x"},
		},
		{
			note: "requirements mounts: short sub+prefix",
			sources: []sourceMock{
				{
					name: "system",
					files: map[string]string{
						"x.rego": `package x
						p := data.imported.lib1.q`,
					},
					requirements: []reqMock{
						{
							name: "lib1",
							mounts: []mount{
								{sub: "lib1", prefix: "imported"},
							},
						},
					},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1
						p := true`,
					},
				},
			},
			excluded: []string{"x/z/data.json"},
			exp: map[string]string{
				"/system/x.rego": `package x
				p := data.imported.lib1.q`,
				"/lib1/lib1.rego": ` package imported
		        p := true`,
			},
			expRoots: []string{"imported", "x"},
		},
		{
			note: "requirements mounts: sub only",
			sources: []sourceMock{
				{
					name: "system",
					files: map[string]string{
						"x.rego": `package x
						p := data.imported.lib1.q`,
					},
					requirements: []reqMock{
						{
							name: "lib1",
							mounts: []mount{
								{sub: "data.lib1"},
							},
						},
					},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1.authz
						p := true`,
					},
				},
			},
			excluded: []string{"x/z/data.json"},
			exp: map[string]string{
				"/system/x.rego": `package x
				p := data.imported.lib1.q`,
				"/lib1/lib1.rego": ` package authz
		        p := true`,
			},
			expRoots: []string{"authz", "x"},
		},
		{
			note: "package conflict: prefix",
			sources: []sourceMock{
				{
					name: "system",
					files: map[string]string{
						"x.rego": `package x
						p := data.lib1.q`,
					},
					requirements: []reqMock{{name: "lib1"}},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1
						p := data.lib1.q`,
					},
					requirements: []reqMock{{name: "lib2"}},
				},
				{
					name: "lib2",
					files: map[string]string{
						"lib2.rego": `package lib2
						q := 7`,
						// add another file that generates a conflict error
						"lib2_other.rego": `package x.y.z

						r := 7`,
					},
				},
			},
			expError: errors.New("requirement \"lib2\" contains conflicting package x.y.z\n- package x from \"system\""),
		},
		{
			note: "package conflict: prefix (reverse)",
			sources: []sourceMock{
				{
					name: "system",
					files: map[string]string{
						"x.rego": `package x.y
						p := data.lib1.q`,
					},
					requirements: []reqMock{{name: "lib1"}},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1
						p := data.lib1.q`,
					},
					requirements: []reqMock{{name: "lib2"}},
				},
				{
					name: "lib2",
					files: map[string]string{
						"lib2.rego": `package lib2
						q := 7`,
						// add another file that generates a conflict error
						"lib2_other.rego": `package x

						r := 7`,
					},
				},
			},
			expError: errors.New("requirement \"lib2\" contains conflicting package x\n- package x.y from \"system\""),
		},
		{
			note: "package conflict: rego and json",
			sources: []sourceMock{
				{
					name: "system",
					files: map[string]string{
						"x.rego": `package x.y
						p := data.x.y.z.w`,
					},
					requirements: []reqMock{{name: "lib1"}},
				},
				{
					name: "lib1",
					files: map[string]string{
						"x/y/z/data.json": `{"w": true}`,
					},
				},
			},
			expError: errors.New("requirement \"lib1\" contains conflicting package x.y.z\n- package x.y from \"system\""),
		},
		{
			note: "missing source",
			sources: []sourceMock{
				{
					files: map[string]string{
						"x.rego": `package x
						p := data.lib1.q`,
					},
					requirements: []reqMock{{name: "libX"}},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1
						p := data.lib1.q`,
					},
				},
			},
			expError: errors.New("missing source \"libX\""),
		},
		{
			note: "shared dependency",
			sources: []sourceMock{
				{
					name: "shared-dep",
					files: map[string]string{
						"x.rego": `package x
						p := data.y.q+data.z.r`,
					},
					requirements: []reqMock{{name: "lib1"}, {name: "lib2"}},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package y
						p := data.z.r`,
					},
					requirements: []reqMock{{name: "lib2"}},
				},
				{
					name: "lib2",
					files: map[string]string{
						"lib2.rego": `package z
						r := 7`,
					},
				},
			},
			exp: map[string]string{
				"/shared-dep/x.rego": `package x
				p := data.y.q+data.z.r`,
				"/lib1/lib1.rego": `package y
				p := data.z.r`,
				"/lib2/lib2.rego": `package z
				r := 7`,
			},
			expRoots: []string{"x", "y", "z"},
		},
		{
			note: "included and excluded files (source level)",
			sources: []sourceMock{
				{
					name: "primary",
					files: map[string]string{
						"x/x.rego": "package x\np := 7",
						"y/y.rego": "package y\nq := 8",
					},
					includedFiles: []string{"x/*"},
					requirements:  []reqMock{{name: "lib"}},
				},
				{
					name: "lib",
					files: map[string]string{
						"x/x.rego":        "package x\np := 9",
						"z/z.rego":        "package z\nq := 10",
						".hidden/ci.json": "{}",
					},
					includedFiles: []string{"z/*", "**/*.json"},
					excludedFiles: []string{".*/*"},
				},
			},
			exp: map[string]string{
				"/primary/x/x.rego": "package x\np := 7",
				"/lib/z/z.rego":     "package z\nq := 10",
			},
			expRoots: []string{"x", "z"},
		},
		{
			note:     "excluded files apply to roots",
			excluded: []string{"lib/x/*"},
			sources: []sourceMock{
				{
					name:         "sys",
					files:        map[string]string{"x.rego": "package x\np { data.lib.y.q }"},
					requirements: []reqMock{{name: "lib"}},
				},
				{
					name: "lib",
					files: map[string]string{
						"lib/x/x.rego": "package x\np { false }", // would conflict w/ package x from previous source
						"lib/y/y.rego": "package lib.y\nq := true",
					},
				},
			},
			exp: map[string]string{
				"/sys/x.rego":       "package x\np { data.lib.y.q }",
				"/lib/lib/y/y.rego": "package lib.y\nq := true",
			},
			expRoots: []string{"x", "lib/y"},
		},
		{
			note: "roots inferred from directory structure for data files",
			sources: []sourceMock{
				{
					name:  "system",
					files: map[string]string{"foo/bar/data.json": `{"A": 7}`},
				},
			},
			exp:      map[string]string{"/data.json": `{"foo":{"bar":{"A":7}}}`},
			expRoots: []string{"foo/bar"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.note, func(t *testing.T) {
			allFiles := map[string]string{}

			for i, src := range tc.sources {
				for k, v := range src.files {
					allFiles[fmt.Sprintf("src%d/%v", i, k)] = trimLeadingWhitespace(v)
				}
			}

			for f, src := range tc.exp {
				tc.exp[f] = trimLeadingWhitespace(src)
			}

			tempfs.WithTempFS(t, allFiles, func(t *testing.T, root string) {

				buf := bytes.NewBuffer(nil)

				var srcs []*builder.Source
				for i, src := range tc.sources {
					var rs []config.Requirement
					for _, r := range src.requirements {
						req := config.Requirement{
							Source: &r.name,
						}
						for i := range r.mounts {
							req.Mounts = append(req.Mounts, config.Mount{Sub: r.mounts[i].sub, Prefix: r.mounts[i].prefix})
						}
						rs = append(rs, req)
					}
					s := builder.NewSource(src.name)
					s.Requirements = rs
					_ = s.AddDir(builder.Dir{
						Path:          fmt.Sprintf("%v/src%d", root, i),
						IncludedFiles: src.includedFiles,
						ExcludedFiles: src.excludedFiles,
					})
					srcs = append(srcs, s)
				}
				b := builder.New().
					WithSources(srcs).
					WithExcluded(tc.excluded).
					WithOutput(buf)

				err := b.Build(t.Context())
				if err != nil {
					if tc.expError != nil {
						if err.Error() == tc.expError.Error() {
							return
						}
						t.Fatalf("Got: %v\nExpected: %v", err, tc.expError)
					} else {
						t.Fatal(err)
					}
				} else if tc.expError != nil {
					t.Fatalf("Build succeeded but expected error: %v", tc.expError)
				}

				bundle, err := bundle.NewReader(buf).Read()
				if err != nil {
					t.Fatal(err)
				}

				if *bundle.Manifest.RegoVersion != 0 {
					t.Fatal("expected rego version to be 0, got", *bundle.Manifest.RegoVersion)
				}

				fileMap := map[string]string{}
				for _, mf := range bundle.Modules {
					fileMap[mf.Path] = string(mf.Raw)
				}
				if len(bundle.Data) > 0 {
					data, _ := json.Marshal(bundle.Data)
					fileMap["/data.json"] = string(data)
				}
				t.Log("got files", slices.Collect(maps.Keys(fileMap)))

				if len(fileMap) != len(tc.exp) {
					for k, v := range fileMap {
						t.Logf("Got %v:\n%v", k, v)
					}
					t.Fatalf("expected %d files, got %d", len(tc.exp), len(fileMap))
				}

				for path, src := range tc.exp {
					if fileMap[path] == "" {
						t.Fatalf("missing file %v", path)
					}

					var equal bool

					switch {
					case strings.HasSuffix(path, ".json"):
						equal = src == fileMap[path]
					case strings.HasSuffix(path, ".rego"):
						got := ast.MustParseModule(fileMap[path])
						exp := ast.MustParseModule(src)

						equal = got.Equal(exp)
					}

					if !equal {
						for k, v := range fileMap {
							t.Logf("Got %v:\n%v", k, v)
						}
						t.Fatalf("Expected %v:\n%v", path, src)
					}
				}

				{
					act, exp := *bundle.Manifest.Roots, tc.expRoots
					if diff := cmp.Diff(exp, act, cmpopts.SortSlices(strings.Compare)); diff != "" {
						t.Errorf("roots: (-want,+got)\n%s", diff)
					}
				}
			})
		})
	}

}

func trimLeadingWhitespace(input string) string {
	lines := strings.Split(input, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimLeft(line, " \t")
	}
	return strings.Join(lines, "\n")
}

func TestBuilder_Build(t *testing.T) {
	tests := []struct {
		name    string // description of this test case
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := builder.New()
			gotErr := b.Build(context.Background())
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Build() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Build() succeeded unexpectedly")
			}
		})
	}
}

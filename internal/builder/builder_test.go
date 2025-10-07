package builder_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/ast"    // nolint:staticcheck
	"github.com/open-policy-agent/opa/bundle" // nolint:staticcheck
	"github.com/pkg/errors"

	"github.com/open-policy-agent/opa-control-plane/internal/builder"
	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/test/tempfs"
)

func TestBuilder(t *testing.T) {

	type sourceMock struct {
		name          string
		files         map[string]string
		requirements  []string
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
					requirements: []string{"lib1"},
				},
				{
					name: "lib1",
					files: map[string]string{
						"/lib1.rego": `package lib1
						import rego.v1
						q if data.lib2.r`,
					},
					requirements: []string{"lib2"},
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
					requirements: []string{"lib1"},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1
						p := data.lib1.q`,
					},
					requirements: []string{"lib2"},
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
			note: "package conflict: prefix",
			sources: []sourceMock{
				{
					name: "system",
					files: map[string]string{
						"x.rego": `package x
						p := data.lib1.q`,
					},
					requirements: []string{"lib1"},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1
						p := data.lib1.q`,
					},
					requirements: []string{"lib2"},
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
					requirements: []string{"lib1"},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1
						p := data.lib1.q`,
					},
					requirements: []string{"lib2"},
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
					requirements: []string{"lib1"},
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
					requirements: []string{"libX"},
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
					requirements: []string{"lib1", "lib2"},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package y
						p := data.z.r`,
					},
					requirements: []string{"lib2"},
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
					requirements:  []string{"lib"},
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
					requirements: []string{"lib"},
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
					for i := range src.requirements {
						rs = append(rs, config.Requirement{Source: &src.requirements[i]})
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

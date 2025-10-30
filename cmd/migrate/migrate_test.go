package migrate

import (
	"encoding/json"
	"io/fs"
	"reflect"
	"sort"
	"strconv"
	"testing"

	"github.com/open-policy-agent/opa-control-plane/cmd/internal/das"
	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/libraries"
	"github.com/open-policy-agent/opa/ast" // nolint:staticcheck
)

func TestLibraryPackageIndex(t *testing.T) {

	index := newLibraryPackageIndex()

	for _, add := range []struct {
		pkg string
		lib string
	}{
		{"libraries/foo/bar", "foo"},
		{"libraries/foo/baz", "foo"},
		{"libraries/qux/corge", "qux"},
	} {
		index.Add(add.pkg, add.lib)
	}

	for i, tc := range []struct {
		path string
		exp  map[string]struct{}
	}{
		{"libraries", map[string]struct{}{"foo": {}, "qux": {}}},
		{"libraries/foo", map[string]struct{}{"foo": {}}},
		{"libraries/foo/bar", map[string]struct{}{"foo": {}}},
		{"libraries/foo/bar/baz", map[string]struct{}{"foo": {}}},
		{"libraries/qux", map[string]struct{}{"qux": {}}},
		{"libraries/qux/corge", map[string]struct{}{"qux": {}}},
		{"libraries/qux/corge/grault", map[string]struct{}{"qux": {}}},
		{"doesnotexist", map[string]struct{}{}},
		{"does/not/exist", map[string]struct{}{}},
		{"libraries/doesnotexist", map[string]struct{}{}},
		{"libraries/foo/doesnotexist", map[string]struct{}{}},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			result := index.Lookup(tc.path)
			if !reflect.DeepEqual(result, tc.exp) {
				t.Fatal("path:", tc.path, "got:", result, "want:", tc.exp)
			}
		})
	}
}

func TestBaseLibIndex(t *testing.T) {

	cases := []struct {
		path string
		lib  string
	}{
		{path: "global", lib: "template.envoy:2.1-conflicts"},
		{path: "global/systemtypes", lib: "template.envoy:2.1-conflicts"},
		{path: "global/systemtypes/envoy:2.1", lib: "template.envoy:2.1-conflicts"},
		{path: "global/systemtypes/envoy:2.1/conflicts", lib: "template.envoy:2.1-conflicts"},
		{path: "global/systemtypes/envoy:2.1/conflicts/entry", lib: "template.envoy:2.1-conflicts"},
		{path: "application", lib: "template.envoy:2.1-entrypoint-application"},
		{path: "system/log", lib: "template.envoy:2.1-entrypoint-log"},
		{path: "system/authz", lib: "template.envoy:2.1-entrypoint-authz"},
		{path: "main", lib: "template.envoy:2.1-entrypoint-main"},
	}

	for _, tc := range cases {
		got := baseLibPackageIndex["template.envoy:2.1"].Lookup(tc.path)
		exp := map[string]struct{}{}
		exp[tc.lib] = struct{}{}
		if !reflect.DeepEqual(exp, got) {
			t.Fatalf("expected %v but got %v", tc.lib, got)
		}
	}
}

func TestPruneConfig(t *testing.T) {

	root, err := config.Parse([]byte(`{
		bundles: {
			sys1: {
				requirements: [{source: app1}],
				labels: {foo: bar}
			}
		},
		stacks: {
			stack1: {
				selector: {foo: [bar]},
				requirements: [{source: lib2}]
			},
			stack2: {
				selector: {
					DONOTMATCH: []
				},
				requirements: [{source: lib3}, {source: libUNUSED3}]
			}
		},
		sources: {
			app1: {
				git: {credentials: sec1},
				requirements: [{source: lib1}],
			},
			lib1: {
				requirements: [{source: lib3}],
				git: {credentials: sec2}
			},
			lib2: {
				requirements: [{source: lib4}],
				git: {credentials: sec3}
			},
			lib3: {
				git: {credentials: sec4}
			},
			lib4: {
				git: {credentials: sec5}
			},
			libUNUSED1: {
				git: {credentials: sec6},
				requirements: [{source: libUNUSED2}]
			},
			libUNUSED2: {
				git: {credentials: sec7},
			},
			libUNUSED3: {
			}
		},
		secrets: {
			sec1: {},
			sec2: {},
			sec3: {},
			sec4: {},
			sec5: {},
			sec6: {},
			sec7: {}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}

	stacks, sources, secrets := pruneConfig(root, true)
	expStacks := []string{"stack2"}
	expSrcs := []string{"libUNUSED1", "libUNUSED2", "libUNUSED3"}
	expSecrets := []string{"sec6", "sec7"}

	gotStacks := make([]string, 0, len(stacks))
	for _, s := range stacks {
		gotStacks = append(gotStacks, s.Name)
	}

	sort.Strings(gotStacks)

	gotSrcs := make([]string, 0, len(sources))
	for _, s := range sources {
		gotSrcs = append(gotSrcs, s.Name)
	}

	sort.Strings(gotSrcs)

	gotSecrets := make([]string, 0, len(secrets))
	for _, s := range secrets {
		gotSecrets = append(gotSecrets, s.Name)
	}

	sort.Strings(gotSecrets)

	if !reflect.DeepEqual(expStacks, gotStacks) {
		t.Fatalf("expected stacks %v but got %v", expStacks, gotStacks)
	}

	if !reflect.DeepEqual(expSrcs, gotSrcs) {
		t.Fatalf("expected libs %v but got %v", expSrcs, gotSrcs)
	}

	if !reflect.DeepEqual(expSecrets, gotSecrets) {
		t.Fatalf("expected secrets %v but got %v", expSecrets, gotSecrets)
	}

	expRoot, err := config.Parse([]byte(`{
		bundles: {
			sys1: {
				requirements: [{source: app1}],
				labels: {foo: bar}
			}
		},
		stacks: {
			stack1: {
				selector: {foo: [bar]},
				requirements: [{source: lib2}]
			},
		},
		sources: {
			app1: {
				git: {credentials: sec1},
				requirements: [{source: lib1}],
			},
			lib1: {
				requirements: [{source: lib3}],
				git: {credentials: sec2}
			},
			lib2: {
				requirements: [{source: lib4}],
				git: {credentials: sec3}
			},
			lib3: {
				git: {credentials: sec4}
			},
			lib4: {
				git: {credentials: sec5}
			},
		},
		secrets: {
			sec1: {},
			sec2: {},
			sec3: {},
			sec4: {},
			sec5: {},
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expRoot, root) {
		t.Fatal("expected root differed from pruned root")
	}
}

func TestMigrateV1Policies(t *testing.T) {

	libraryFile := func(path string) string {
		bs, err := fs.ReadFile(libraries.FS, path)
		if err != nil {
			panic(err)
		}
		return string(bs)
	}

	cases := []struct {
		name     string
		policies []*das.V1Policy
		nsPrefix string
		gitRoots []string
		typeLib  string
		expFiles config.Files
		expReqs  []string
	}{
		{
			name:     "envoy21: no policies, no git",
			policies: []*das.V1Policy{},
			nsPrefix: "systems/x1234",
			gitRoots: []string{},
			typeLib:  "template.envoy:2.1",
			expFiles: config.Files{},
			expReqs:  []string{"template.envoy:2.1"},
		},
		{
			name: "envoy21: git owns policy/ but not system/ which differs",
			policies: []*das.V1Policy{
				{
					Package: "systems/x1234/policy/ingress",
					Modules: map[string]string{"rules.rego": `package policy.ingress`},
				},
				{
					Package: "systems/x1234/system/log",
					Modules: map[string]string{"mask.rego": `package system.log`},
				},
			},
			nsPrefix: "systems/x1234",
			gitRoots: []string{"policy"},
			typeLib:  "template.envoy:2.1",
			expFiles: config.Files{
				"system/log/mask.rego": `package system.log`,
			},
			expReqs: []string{
				"template.envoy:2.1-entrypoint-application",
				"template.envoy:2.1-entrypoint-main",
				"template.envoy:2.1-entrypoint-authz",
				"template.envoy:2.1-conflicts",
			},
		},
		{
			name: "envoy21: git owns policy/ but not system/ which is identical to library",
			policies: []*das.V1Policy{
				{
					Package: "systems/x1234/policy/ingress",
					Modules: map[string]string{"rules.rego": `package policy.ingress`},
				},
				{
					Package: "systems/x1234/system/log",
					Modules: map[string]string{"mask.rego": libraryFile("envoy-v2.1/log/system/log/mask.rego")},
				},
				{
					Package: "systems/x1234/system/authz",
					Modules: map[string]string{"authz.rego": libraryFile("envoy-v2.1/authz/system/authz/authz.rego")},
				},
			},
			nsPrefix: "systems/x1234",
			gitRoots: []string{"policy"},
			typeLib:  "template.envoy:2.1",
			expReqs:  []string{"template.envoy:2.1"},
		},
		{
			name: "envoy21: git owns policy/ and system/",
			policies: []*das.V1Policy{
				{
					Package: "systems/x1234/policy/ingress",
					Modules: map[string]string{"rules.rego": `package policy.ingress`},
				},
				{
					Package: "systems/x1234/system/log",
					Modules: map[string]string{"mask.rego": `package system.log`},
				},
				{
					Package: "systems/x1234/system/authz",
					Modules: map[string]string{"authz.rego": `package system.authz`},
				},
			},
			nsPrefix: "systems/x1234",
			gitRoots: []string{"policy", "system"},
			typeLib:  "template.envoy:2.1",
			expFiles: config.Files{},
			expReqs: []string{
				"template.envoy:2.1-entrypoint-application",
				"template.envoy:2.1-entrypoint-main",
				"template.envoy:2.1-conflicts",
			},
		},
		{
			name: "file-level git roots",
			policies: []*das.V1Policy{
				{
					Package: "systems/x1234/policy",
					Modules: map[string]string{
						"policy.rego": `package policy`,
						"rules.rego":  "package policy\np := 7",
					},
				},
			},
			nsPrefix: "systems/x1234",
			gitRoots: []string{"policy/policy.rego"},
			expFiles: config.Files{
				"policy/rules.rego": "package policy\np := 7",
			},
		},
		{
			name: "maximal git roots",
			policies: []*das.V1Policy{
				{
					Package: "systems/x1234/policy",
					Modules: map[string]string{
						"policy.rego": `package policy`,
					},
				},
			},
			nsPrefix: "systems/x1234",
			gitRoots: []string{""},
			expFiles: config.Files{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files, reqs := migrateV1Policies(getSystemTypeLib(tc.typeLib), tc.nsPrefix, tc.policies, tc.gitRoots)

			if !tc.expFiles.Equal(files) {
				t.Fatalf("expected files %v but got %v", tc.expFiles, files)
			}

			var expReqs []config.Requirement
			for _, r := range tc.expReqs {
				expReqs = append(expReqs, config.Requirement{Source: &r})
			}

			if !reflect.DeepEqual(expReqs, reqs) {
				t.Fatalf("expected requirements %v but got %v", expReqs, reqs)
			}
		})
	}

}

func TestMigrateV1Selector(t *testing.T) {

	tests := []struct {
		note     string
		module   string
		selector string
		exclude  string
	}{
		{
			note: "include only",
			module: `
				package x

				systems[system_id] {
					include := {"foo": {"bar"}, "baz": {"qux", "corge"}, "grault": set()}
					exclude := {}
					match.all(data.metadata[system_id].labels, include, exclude)
				}`,
			selector: `
				{
					"foo": ["bar"],
					"baz": ["corge", "qux"],
					"grault": [],
					"system-type": ["foo-v1"]
				}
			`,
		},
		{
			note: "include and exclude",
			module: `
					package x

					systems[system_id] {
						include := {"foo": {"bar"}}
						exclude := {"baz": {"qux"}}
						match.all(data.metadata[system_id].labels, include, exclude)
					}
			`,
			selector: `
					{
						"foo": ["bar"],
						"system-type": ["foo-v1"]
					}
				`,
			exclude: `
				{
					"baz": ["qux"]
				}
			`,
		},
		{
			note: "missing match_all causes static match",
			module: `
					package x

					systems[system_id] {
						include := {"foo": {"bar"}}
						exclude := {}
						not match.all(data.metadata[system_id].labels, include, exclude)
					}
			`,
			selector: `
					{
						"stack-abcd": ["*"],
						"system-type": ["foo-v1"]
					}
				`,
		},
		{
			note: "multiple rules cause static match",
			module: `
					package x

					systems[system_id] {
						include := {"foo": {"bar"}, "baz": {"qux", "corge"}, "grault": set()}
						exclude := {}
						match.all(data.metadata[system_id].labels, include, exclude)
					}

					systems[system_id] {
						include := {"another": {"label"}}
						exclude := {}
						match.all(data.metadata[system_id].labels, include, exclude)
					}
			`,
			selector: `
					{
						"stack-abcd": ["*"],
						"system-type": ["foo-v1"]
					}
				`,
		},
		{
			note: "missing systems rule cause static match",
			module: `package x

					select[system_id] {  # this is not a rule name that is recognized by selector logic
						include := {"foo": {"bar"}, "baz": {"qux", "corge"}, "grault": set()}
						exclude := {}
						match.all(data.metadata[system_id].labels, include, exclude)
					}

			`,
			selector: `
					{
						"stack-abcd": ["*"],
						"system-type": ["foo-v1"]
					}
				`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.note, func(t *testing.T) {
			module := ast.MustParseModule(tc.module)
			var expectedSelector config.Selector
			if err := json.Unmarshal([]byte(tc.selector), &expectedSelector); err != nil {
				t.Fatal(err)
			}
			var expectedExclude *config.Selector
			if tc.exclude != "" {
				if err := json.Unmarshal([]byte(tc.exclude), &expectedExclude); err != nil {
					t.Fatal(err)
				}
			}
			var stack das.V1Stack
			stack.Id = "abcd"
			stack.Type = "foo-v1"
			selector, exclude, err := migrateV1Selector(&stack, module)
			if err != nil {
				t.Fatal(err)
			}
			if !selector.Equal(expectedSelector) {
				t.Fatal("expected", expectedSelector, "got", selector)
			}
			if !expectedExclude.PtrEqual(exclude) {
				t.Fatal("expected", expectedExclude, "got", exclude)
			}
		})
	}
}

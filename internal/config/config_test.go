package config_test

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/styrainc/opa-control-plane/internal/config"
	"gopkg.in/yaml.v3"
)

func TestParseSecretResolve(t *testing.T) {

	result, err := config.Parse(bytes.NewReader([]byte(`{
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
	}`)))

	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("OPACTL_PASSWORD", "passw0rd")

	value, err := result.Sources["foo"].Git.Credentials.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	exp := config.SecretBasicAuth{
		Username: "bob",
		Password: "passw0rd",
	}

	if !reflect.DeepEqual(value, exp) {
		t.Fatalf("expected: %v\n\ngot: %v", exp, value)
	}
}

func TestFilesMarshallingRoundtrip(t *testing.T) {

	cfg, err := config.Parse(bytes.NewBufferString(`{
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

	cfg2, err := config.Parse(bytes.NewBuffer(bs))
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

	_, err := config.Parse(bytes.NewBufferString(`{
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

	config, err := config.Parse(bytes.NewBufferString(`{
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

	config, err := config.Parse(bytes.NewBufferString(`{
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

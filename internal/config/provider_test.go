package config_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/google/go-cmp/cmp"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/test/tempfs"
	extconfig "github.com/open-policy-agent/opa-control-plane/pkg/config"
)

const providersYAML = `
sources:
  app:
    providers:
      - name: users
        type: example.custom-source
        path: some/prefix
        port: 8080
        tags: [a, b]
        nested:
          enabled: true
      - name: minimal
        type: other
`

func TestParseProviders(t *testing.T) {
	root, err := config.Parse([]byte(providersYAML))
	if err != nil {
		t.Fatal(err)
	}
	exp := extconfig.Providers{
		{
			Name: "users",
			Type: "example.custom-source",
			Path: "some/prefix",
			Config: map[string]any{
				"port":   float64(8080), // normalized to what JSON decoding yields
				"tags":   []any{"a", "b"},
				"nested": map[string]any{"enabled": true},
			},
		},
		{Name: "minimal", Type: "other"},
	}
	if diff := cmp.Diff(exp, root.Sources["app"].Providers); diff != "" {
		t.Errorf("providers (-want,+got):\n%s", diff)
	}
}

func TestProvidersYAMLAndJSONEqual(t *testing.T) {
	fromYAML, err := config.Parse([]byte(providersYAML))
	if err != nil {
		t.Fatal(err)
	}

	// The REST API and the database use JSON.
	bs, err := json.Marshal(fromYAML.Sources["app"])
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON config.Source
	if err := json.Unmarshal(bs, &fromJSON); err != nil {
		t.Fatal(err)
	}
	if !fromYAML.Sources["app"].Equal(&fromJSON) {
		t.Errorf("expected equal sources, got\nYAML: %+v\nJSON: %+v", fromYAML.Sources["app"].Providers, fromJSON.Providers)
	}
}

func TestProviderMarshalling(t *testing.T) {
	p := extconfig.Provider{
		Name:   "users",
		Type:   "example.custom-source",
		Path:   "some/prefix",
		Config: map[string]any{"param1": "value"},
	}

	t.Run("JSON is flat", func(t *testing.T) {
		bs, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(bs, &got); err != nil {
			t.Fatal(err)
		}
		exp := map[string]any{"name": "users", "type": "example.custom-source", "path": "some/prefix", "param1": "value"}
		if diff := cmp.Diff(exp, got); diff != "" {
			t.Errorf("(-want,+got):\n%s", diff)
		}
	})

	t.Run("JSON omits empty path", func(t *testing.T) {
		bs, err := json.Marshal(extconfig.Provider{Name: "a", Type: "b"})
		if err != nil {
			t.Fatal(err)
		}
		if got := string(bs); got != `{"name":"a","type":"b"}` {
			t.Errorf("got %s", got)
		}
	})

	for name, roundtrip := range map[string]func(extconfig.Provider) (extconfig.Provider, error){
		"JSON": func(in extconfig.Provider) (out extconfig.Provider, err error) {
			bs, err := json.Marshal(in)
			if err == nil {
				err = json.Unmarshal(bs, &out)
			}
			return out, err
		},
		"YAML": func(in extconfig.Provider) (out extconfig.Provider, err error) {
			bs, err := yaml.Marshal(in)
			if err == nil {
				err = yaml.Unmarshal(bs, &out)
			}
			return out, err
		},
	} {
		t.Run(name+" roundtrip", func(t *testing.T) {
			got, err := roundtrip(p)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(p, got); diff != "" {
				t.Errorf("(-want,+got):\n%s", diff)
			}
		})
	}
}

func TestProviderDecodeErrors(t *testing.T) {
	for key, entry := range map[string]string{
		"name": `{"name": 1, "type": "t"}`,
		"type": `{"name": "n", "type": ["t"]}`,
		"path": `{"name": "n", "type": "t", "path": {}}`,
	} {
		var p extconfig.Provider
		err := json.Unmarshal([]byte(entry), &p)
		if err == nil || !strings.Contains(err.Error(), "provider "+key+": expected a string") {
			t.Errorf("%s: expected string error, got %v", key, err)
		}
	}
}

func TestValidateProvidersSchema(t *testing.T) {
	cases := []struct {
		note  string
		entry string
		exp   string // substring of the validation error; empty for valid
	}{
		{note: "valid", entry: `{name: a, type: t, anything: [1]}`},
		{note: "missing name", entry: `{type: t}`, exp: "missing property 'name'"},
		{note: "missing type", entry: `{name: a}`, exp: "missing property 'type'"},
		{note: "empty name", entry: `{name: "", type: t}`, exp: "/providers/0/name"},
		{note: "empty type", entry: `{name: a, type: ""}`, exp: "/providers/0/type"},
		{note: "path not a string", entry: `{name: a, type: t, path: 1}`, exp: "/providers/0/path"},
	}
	for _, tc := range cases {
		t.Run(tc.note, func(t *testing.T) {
			_, err := config.Parse([]byte("sources:\n  app:\n    providers:\n      - " + tc.entry + "\n"))
			switch {
			case tc.exp == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.exp != "" && (err == nil || !strings.Contains(err.Error(), tc.exp)):
				t.Fatalf("expected error containing %q, got %v", tc.exp, err)
			}
		})
	}
}

func TestProvidersEqual(t *testing.T) {
	a := extconfig.Provider{Name: "a", Type: "t", Config: map[string]any{"k": "v"}}
	b := extconfig.Provider{Name: "b", Type: "t"}

	if !(extconfig.Providers{a, b}).Equal(extconfig.Providers{b, a}) {
		t.Error("expected order not to matter")
	}
	changed := a
	changed.Config = map[string]any{"k": "other"}
	if (extconfig.Providers{a, b}).Equal(extconfig.Providers{changed, b}) {
		t.Error("expected a config change to make providers unequal")
	}

	src := config.Source{Name: "app", Providers: extconfig.Providers{a}}
	other := config.Source{Name: "app", Providers: extconfig.Providers{changed}}
	if src.Equal(&other) {
		t.Error("expected a provider change to make sources unequal")
	}
}

func TestMergeReplacesProviders(t *testing.T) {
	files := map[string]string{
		"config.d/1.yaml": `
sources:
  app:
    providers:
      - {name: one, type: t, param: 1}
      - {name: two, type: t}
`,
		"config.d/2.yaml": `
sources:
  app:
    providers:
      - {name: three, type: t, param: 3}
`,
	}
	tempfs.WithTempFS(t, files, func(t *testing.T, dir string) {
		bs, err := config.Merge([]string{dir}, false)
		if err != nil {
			t.Fatal(err)
		}
		root, err := config.Parse(bs)
		if err != nil {
			t.Fatal(err)
		}
		exp := extconfig.Providers{{Name: "three", Type: "t", Config: map[string]any{"param": float64(3)}}}
		if diff := cmp.Diff(exp, root.Sources["app"].Providers); diff != "" {
			t.Errorf("providers (-want,+got):\n%s", diff)
		}
	})
}

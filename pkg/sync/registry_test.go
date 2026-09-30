package sync_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
)

type fakeProvider struct {
	typ    string
	schema string
}

func (f fakeProvider) Type() string                     { return f.typ }
func (f fakeProvider) ConfigSchema() json.RawMessage    { return json.RawMessage(f.schema) }
func (fakeProvider) Parse(json.RawMessage) (any, error) { return nil, nil }
func (fakeProvider) New(context.Context, pkgsync.ProviderParams) (pkgsync.Synchronizer, error) {
	return nil, nil
}

const strictSchema = `{
	"type": "object",
	"properties": {"param1": {"type": "string"}},
	"required": ["param1"],
	"additionalProperties": false
}`

func TestRegistryRegister(t *testing.T) {
	cases := []struct {
		note   string
		p      pkgsync.SourceProvider
		expErr string
	}{
		{note: "valid", p: fakeProvider{typ: "my-source", schema: strictSchema}},
		{note: "dotted type", p: fakeProvider{typ: "example.custom-source", schema: `{}`}},
		{note: "nil", p: nil, expErr: "source provider is nil"},
		{note: "empty type", p: fakeProvider{typ: "", schema: `{}`}, expErr: `source provider type ""`},
		{note: "uppercase type", p: fakeProvider{typ: "MySource", schema: `{}`}, expErr: `source provider type "MySource"`},
		{note: "schema not an object", p: fakeProvider{typ: "x", schema: `[]`}, expErr: "must be a JSON object"},
		{note: "schema not for an object", p: fakeProvider{typ: "x", schema: `{"type": "string"}`}, expErr: `"type" must be "object"`},
		{note: "reserved key", p: fakeProvider{typ: "x", schema: `{"properties": {"path": {}}}`}, expErr: `must not declare reserved key "path"`},
		{note: "invalid schema", p: fakeProvider{typ: "x", schema: `{"minProperties": "two"}`}, expErr: `source provider "x": config schema:`},
	}
	for _, tc := range cases {
		t.Run(tc.note, func(t *testing.T) {
			err := pkgsync.NewSourceProviderRegistry().Register(tc.p)
			switch {
			case tc.expErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.expErr != "" && (err == nil || !strings.Contains(err.Error(), tc.expErr)):
				t.Fatalf("expected error containing %q, got %v", tc.expErr, err)
			}
		})
	}
}

func TestRegistryDuplicate(t *testing.T) {
	r := pkgsync.NewSourceProviderRegistry()
	if err := r.Register(fakeProvider{typ: "a", schema: `{}`}); err != nil {
		t.Fatal(err)
	}
	err := r.Register(fakeProvider{typ: "a", schema: `{}`})
	if err == nil || err.Error() != `source provider "a" already registered` {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestRegistryGetTypes(t *testing.T) {
	r := pkgsync.NewSourceProviderRegistry()
	for _, typ := range []string{"b", "a"} {
		if err := r.Register(fakeProvider{typ: typ, schema: `{}`}); err != nil {
			t.Fatal(err)
		}
	}
	if p, ok := r.Get("a"); !ok || p.Type() != "a" {
		t.Errorf("Get(a) = %v, %v", p, ok)
	}
	if _, ok := r.Get("c"); ok {
		t.Error("Get(c): expected not found")
	}
	if got := r.Types(); strings.Join(got, ",") != "a,b" {
		t.Errorf("Types() = %v", got)
	}
}

func compileSchema(t *testing.T, raw json.RawMessage) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	if err := c.AddResource("providers.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("providers.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRegistrySchema(t *testing.T) {
	r := pkgsync.NewSourceProviderRegistry()
	for _, p := range []pkgsync.SourceProvider{
		fakeProvider{typ: "strict", schema: strictSchema},
		fakeProvider{typ: "lenient", schema: `{}`},
		// "#/..." refs must keep resolving within the provider's own schema.
		fakeProvider{typ: "with-defs", schema: `{
			"$defs": {"port": {"type": "integer"}},
			"properties": {"port": {"$ref": "#/$defs/port"}}
		}`},
	} {
		if err := r.Register(p); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := r.Schema()
	if err != nil {
		t.Fatal(err)
	}
	schema := compileSchema(t, raw)

	cases := []struct {
		note  string
		entry string
		valid bool
	}{
		{"strict", `{"name": "a", "type": "strict", "param1": "x"}`, true},
		{"strict with path", `{"name": "a", "type": "strict", "path": "p", "param1": "x"}`, true},
		{"strict missing field", `{"name": "a", "type": "strict"}`, false},
		{"strict unknown field", `{"name": "a", "type": "strict", "param1": "x", "extra": 1}`, false},
		{"lenient", `{"name": "a", "type": "lenient", "anything": [1, 2]}`, true},
		{"missing name", `{"type": "lenient"}`, false},
		{"empty name", `{"name": "", "type": "lenient"}`, false},
		{"missing type", `{"name": "a"}`, false},
		{"unknown type", `{"name": "a", "type": "nope"}`, false},
		{"path not a string", `{"name": "a", "type": "lenient", "path": 1}`, false},
		{"defs ref valid", `{"name": "a", "type": "with-defs", "port": 8080}`, true},
		{"defs ref invalid", `{"name": "a", "type": "with-defs", "port": "http"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.note, func(t *testing.T) {
			inst, err := jsonschema.UnmarshalJSON(strings.NewReader(tc.entry))
			if err != nil {
				t.Fatal(err)
			}
			err = schema.Validate(inst)
			if tc.valid && err != nil {
				t.Errorf("expected valid, got %v", err)
			}
			if !tc.valid && err == nil {
				t.Error("expected invalid")
			}
		})
	}
}

func TestRegistrySchemaEmpty(t *testing.T) {
	raw, err := pkgsync.NewSourceProviderRegistry().Schema()
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"name": "a", "type": "x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := compileSchema(t, raw).Validate(inst); err == nil {
		t.Error("expected no entry to be valid with no providers registered")
	}
}

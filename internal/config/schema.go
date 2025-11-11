package config

import (
	"bytes"
	"encoding/json"

	"github.com/santhosh-tekuri/jsonschema/v6"
	schemareflector "github.com/swaggest/jsonschema-go"

	ext_config "github.com/open-policy-agent/opa-control-plane/config"
)

var rootSchema *jsonschema.Schema

func init() {
	js, err := jsonschema.UnmarshalJSON(bytes.NewReader(ext_config.Schema()))
	if err != nil {
		panic(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource("schema.json", js); err != nil {
		panic(err)
	}

	rootSchema, err = compiler.Compile("schema.json")
	if err != nil {
		panic(err)
	}
}

func ReflectSchema() ([]byte, error) {
	reflector := schemareflector.Reflector{}

	s, err := reflector.Reflect(Root{})
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(s, "", "  ")
}

func (Duration) PrepareJSONSchema(schema *schemareflector.Schema) error {
	schema.Type = nil
	schema.AddType(schemareflector.String)
	return nil
}

// We do this so that the following YAML config is considered valid:
//
//	sources:
//	  empty-source:
//
// This would be desirable when you want a source to only be there for
// PUT data updates.
func (*Source) PrepareJSONSchema(schema *schemareflector.Schema) error {
	schema.AddType(schemareflector.Null)
	return nil
}

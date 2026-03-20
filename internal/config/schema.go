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

func (*Selector) PrepareJSONSchema(schema *schemareflector.Schema) error {
	str := schemareflector.String.ToSchemaOrBool()

	arr := schemareflector.Array.ToSchemaOrBool()
	arr.TypeObject.ItemsEns().SchemaOrBool = &str

	schema.Type = nil
	schema.AddType(schemareflector.Object)
	schema.AdditionalProperties = &arr

	return nil
}

package config

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"

	"github.com/goccy/go-yaml"
	schemareflector "github.com/swaggest/jsonschema-go"

	internalutil "github.com/open-policy-agent/opa-control-plane/pkg/util"
)

// Provider is an entry of a source's `providers:` list, handled by the
// source provider registered for its Type. For example:
//
//	providers:
//	  - name: users
//	    type: my-source
//	    path: some/prefix
//	    param1: value
//
// Name, Type and Path are handled by OCP; all other keys are the
// provider's own configuration, kept in Config.
type Provider struct {
	Name   string         // required, unique within the source
	Type   string         // required, selects the source provider
	Path   string         // optional prefix the entry's content is placed under
	Config map[string]any // all other keys
}

// Providers is a slice of Provider.
type Providers []Provider

// Reserved keys of a provider entry.
const (
	providerKeyName = "name"
	providerKeyType = "type"
	providerKeyPath = "path"
)

func (p *Provider) UnmarshalJSON(bs []byte) error {
	var m map[string]any
	if err := json.Unmarshal(bs, &m); err != nil {
		return fmt.Errorf("failed to decode provider: %w", err)
	}
	return p.fromMap(m)
}

func (p *Provider) UnmarshalYAML(bs []byte) error {
	var m map[string]any
	if err := yaml.Unmarshal(bs, &m); err != nil {
		return fmt.Errorf("failed to decode provider: %w", err)
	}
	return p.fromMap(m)
}

func (p *Provider) fromMap(m map[string]any) error {
	var out Provider
	for key, dst := range map[string]*string{
		providerKeyName: &out.Name,
		providerKeyType: &out.Type,
		providerKeyPath: &out.Path,
	} {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("provider %s: expected a string, got %T", key, v)
		}
		*dst = s
		delete(m, key)
	}

	if len(m) > 0 {
		// Normalize through JSON, so the same configuration compares equal
		// whether it was decoded from YAML (e.g. integers) or JSON (float64).
		bs, err := json.Marshal(m)
		if err != nil {
			return fmt.Errorf("provider %q: %w", out.Name, err)
		}
		if err := json.Unmarshal(bs, &out.Config); err != nil {
			return fmt.Errorf("provider %q: %w", out.Name, err)
		}
	}

	*p = out
	return nil
}

func (p Provider) toMap() map[string]any {
	m := make(map[string]any, len(p.Config)+3)
	maps.Copy(m, p.Config)
	m[providerKeyName] = p.Name
	m[providerKeyType] = p.Type
	if p.Path != "" {
		m[providerKeyPath] = p.Path
	}
	return m
}

func (p Provider) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.toMap())
}

func (p Provider) MarshalYAML() (any, error) {
	return p.toMap(), nil
}

// PrepareJSONSchema implements the jsonschema-go Preparer interface. The
// schema only covers the reserved keys; each provider validates its own.
func (*Provider) PrepareJSONSchema(schema *schemareflector.Schema) error {
	str := schemareflector.String.ToSchemaOrBool()
	nonEmpty := schemareflector.String.ToSchemaOrBool()
	nonEmpty.TypeObject.WithMinLength(1)
	anything := schemareflector.SchemaOrBool{TypeBoolean: new(true)}

	schema.Type = nil
	schema.AddType(schemareflector.Object)
	schema.Properties = map[string]schemareflector.SchemaOrBool{
		providerKeyName: nonEmpty,
		providerKeyType: nonEmpty,
		providerKeyPath: str,
	}
	schema.Required = []string{providerKeyName, providerKeyType}
	schema.AdditionalProperties = &anything
	return nil
}

func (p *Provider) Equal(other *Provider) bool {
	return internalutil.FastEqual(p, other, func(p, other *Provider) bool {
		return p.Name == other.Name &&
			p.Type == other.Type &&
			p.Path == other.Path &&
			reflect.DeepEqual(p.Config, other.Config)
	})
}

func (a Providers) Equal(b Providers) bool {
	return internalutil.SetEqual(a, b, func(p Provider) string { return p.Name }, func(a, b Provider) bool { return a.Equal(&b) })
}

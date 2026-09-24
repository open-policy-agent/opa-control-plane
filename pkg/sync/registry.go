package sync

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	gosync "sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// reservedKeys are the keys of a `providers:` entry that OCP handles itself.
var reservedKeys = []string{"name", "type", "path"}

var validType = regexp.MustCompile(`^[a-z][a-z0-9._-]*$`)

// SourceProviderRegistry holds the SourceProviders a service can use, keyed
// by type.
type SourceProviderRegistry struct {
	mu        gosync.RWMutex
	providers map[string]SourceProvider
	schemas   map[string]map[string]any // parsed ConfigSchema, by type
}

// NewSourceProviderRegistry returns an empty registry.
func NewSourceProviderRegistry() *SourceProviderRegistry {
	return &SourceProviderRegistry{
		providers: map[string]SourceProvider{},
		schemas:   map[string]map[string]any{},
	}
}

// Register adds p to the registry. It fails if p's type is invalid or
// already registered, or if its ConfigSchema is not a valid JSON Schema for
// an object or declares one of the reserved keys (name, type, path).
func (r *SourceProviderRegistry) Register(p SourceProvider) error {
	if p == nil {
		return errors.New("source provider is nil")
	}
	t := p.Type()
	if !validType.MatchString(t) {
		return fmt.Errorf("source provider type %q: must start with a lowercase letter and contain only lowercase letters, digits, '.', '_' and '-'", t)
	}
	schema, err := parseConfigSchema(t, p.ConfigSchema())
	if err != nil {
		return fmt.Errorf("source provider %q: config schema: %w", t, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.providers[t]; ok {
		return fmt.Errorf("source provider %q already registered", t)
	}
	r.providers[t] = p
	r.schemas[t] = schema
	return nil
}

// Get returns the provider registered for type t.
func (r *SourceProviderRegistry) Get(t string) (SourceProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[t]
	return p, ok
}

// Types returns the registered types, sorted.
func (r *SourceProviderRegistry) Types() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Sorted(maps.Keys(r.providers))
}

// Schema returns a JSON Schema for a single `providers:` entry: a oneOf with
// one alternative per registered type, each combining the reserved keys with
// that provider's ConfigSchema. With no providers registered, no entry is
// valid.
func (r *SourceProviderRegistry) Schema() (json.RawMessage, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.providers) == 0 {
		return json.RawMessage("false"), nil
	}
	alternatives := make([]any, 0, len(r.schemas))
	for _, t := range slices.Sorted(maps.Keys(r.schemas)) {
		alternatives = append(alternatives, entrySchema(t, r.schemas[t]))
	}
	return json.Marshal(map[string]any{"oneOf": alternatives})
}

// schemaID is the $id given to a provider's entry schema. Giving each
// alternative its own $id keeps "#/..." references in a provider's schema
// (e.g. to its $defs) resolving within that provider's schema once embedded.
func schemaID(t string) string {
	return "urn:opa-control-plane:source-provider:" + t
}

// parseConfigSchema checks that raw is a valid JSON Schema for an object that
// does not declare reserved keys, and returns it parsed.
func parseConfigSchema(t string, raw json.RawMessage) (map[string]any, error) {
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, fmt.Errorf("must be a JSON object: %w", err)
	}
	if typ, ok := schema["type"]; ok && typ != "object" {
		return nil, fmt.Errorf(`"type" must be "object", got %v`, typ)
	}
	if props, ok := schema["properties"]; ok {
		props, ok := props.(map[string]any)
		if !ok {
			return nil, errors.New(`"properties" must be an object`)
		}
		for _, k := range reservedKeys {
			if _, ok := props[k]; ok {
				return nil, fmt.Errorf("must not declare reserved key %q", k)
			}
		}
	}

	// Compile the combined entry schema, so an invalid schema is caught
	// here rather than when it is first used. It goes through JSON and the
	// library's own decoder, as it will when used.
	bs, err := json.Marshal(entrySchema(t, schema))
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(bs))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	if err := c.AddResource(schemaID(t), doc); err != nil {
		return nil, err
	}
	if _, err := c.Compile(schemaID(t)); err != nil {
		return nil, err
	}
	return schema, nil
}

// entrySchema combines a provider's config schema with the reserved keys
// into the schema for a complete entry of type t.
func entrySchema(t string, config map[string]any) map[string]any {
	s := maps.Clone(config)
	s["$id"] = schemaID(t)
	s["type"] = "object"

	props := map[string]any{}
	if p, ok := config["properties"].(map[string]any); ok {
		maps.Copy(props, p)
	}
	props["name"] = map[string]any{"type": "string", "minLength": 1}
	props["type"] = map[string]any{"const": t}
	props["path"] = map[string]any{"type": "string"}
	s["properties"] = props

	required := []any{"name", "type"}
	if req, ok := config["required"].([]any); ok {
		required = append(required, req...)
	}
	s["required"] = required
	return s
}

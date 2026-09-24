// Package providers implements the built-in source types (git, http and s3)
// as SourceProviders.
//
// Built-in types are configured through a source's git and datasources
// fields rather than `providers:` entries, so the service passes their
// already-parsed configuration to New directly and never calls Parse.
package providers

import (
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa-control-plane/pkg/metrics"
	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
)

// Built-in source types.
const (
	TypeGit  = "git"
	TypeHTTP = "http"
	TypeS3   = "s3"
)

// Builtins returns a registry holding the built-in providers.
func Builtins(m *metrics.Metrics) (*pkgsync.SourceProviderRegistry, error) {
	r := pkgsync.NewSourceProviderRegistry()
	for _, p := range []pkgsync.SourceProvider{NewGit(m), HTTP{}, S3{}} {
		if err := r.Register(p); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// builtinSchema is the ConfigSchema of built-in types. They are not
// configured through `providers:` entries, so it is never used to validate
// configuration.
var builtinSchema = json.RawMessage(`{"type": "object"}`)

func errParse(t, field string) error {
	return fmt.Errorf("source type %q can't be used in providers, use the source's %s field", t, field)
}

func errConfig(t string, cfg any) error {
	return fmt.Errorf("source type %q: unexpected config type %T", t, cfg)
}

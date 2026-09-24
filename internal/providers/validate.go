package providers

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
)

// Validate checks src's provider entries against the source providers in
// reg (which may be nil, meaning none are registered). It returns all
// problems found, joined.
func Validate(reg *pkgsync.SourceProviderRegistry, src *config.Source) error {
	var errs []error
	seen := make(map[string]struct{}, len(src.Providers))
	for i, p := range src.Providers {
		label := fmt.Sprintf("provider %q", p.Name)
		if p.Name == "" {
			label = fmt.Sprintf("provider #%d", i+1)
			errs = append(errs, fmt.Errorf("source %q: %s: name is required", src.Name, label))
		} else if _, ok := seen[p.Name]; ok {
			errs = append(errs, fmt.Errorf("source %q: %s: duplicate name", src.Name, label))
		}
		seen[p.Name] = struct{}{}

		if _, _, err := ParseEntry(reg, p); err != nil {
			errs = append(errs, fmt.Errorf("source %q: %s: %w", src.Name, label, err))
		}
	}
	return errors.Join(errs...)
}

// ParseEntry checks a single provider entry (all but its name, which is
// checked against the rest of its source by Validate) and returns its source
// provider and the configuration its Parse returned.
func ParseEntry(reg *pkgsync.SourceProviderRegistry, p config.Provider) (pkgsync.SourceProvider, any, error) {
	if err := validatePath(p.Path); err != nil {
		return nil, nil, err
	}

	switch p.Type {
	case "":
		return nil, nil, errors.New("type is required")
	case TypeGit:
		return nil, nil, fmt.Errorf("type %q can't be used in providers, use the source's git field", p.Type)
	case TypeHTTP, TypeS3:
		return nil, nil, fmt.Errorf("type %q can't be used in providers, use the source's datasources field", p.Type)
	}

	var prov pkgsync.SourceProvider
	var ok bool
	if reg != nil {
		prov, ok = reg.Get(p.Type)
	}
	if !ok {
		return nil, nil, fmt.Errorf("unknown type %q", p.Type)
	}

	cfg := p.Config
	if cfg == nil {
		cfg = map[string]any{}
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := prov.Parse(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("type %q: %w", p.Type, err)
	}
	return prov, parsed, nil
}

// validatePath checks the entry's path, a prefix for its content that is
// joined onto the entry's own directory: ".." could escape that directory,
// and a leading "/" would be ignored rather than mean what it suggests.
func validatePath(p string) error {
	if p == "" {
		return nil
	}
	if path.IsAbs(p) || filepath.IsAbs(p) {
		return fmt.Errorf("path %q must be relative", p)
	}
	if slices.Contains(strings.Split(filepath.ToSlash(p), "/"), "..") {
		return fmt.Errorf("path %q must not contain \"..\"", p)
	}
	return nil
}

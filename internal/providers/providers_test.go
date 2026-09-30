package providers_test

import (
	"strings"
	"testing"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/gitsync"
	"github.com/open-policy-agent/opa-control-plane/internal/httpsync"
	"github.com/open-policy-agent/opa-control-plane/internal/providers"
	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
)

func TestBuiltins(t *testing.T) {
	r, err := providers.Builtins(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.Types(), ","); got != "git,http,s3" {
		t.Fatalf("Types() = %v", got)
	}
}

func TestNew(t *testing.T) {
	r, err := providers.Builtins(nil)
	if err != nil {
		t.Fatal(err)
	}
	get := func(typ string) pkgsync.SourceProvider {
		p, ok := r.Get(typ)
		if !ok {
			t.Fatalf("%s not registered", typ)
		}
		return p
	}

	t.Run("git", func(t *testing.T) {
		s, err := get("git").New(t.Context(), pkgsync.ProviderParams{
			SourceName: "src",
			Config:     config.Git{Repo: "https://example.com/repo.git"},
			Dir:        t.TempDir(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := s.(*gitsync.Synchronizer); !ok {
			t.Errorf("got %T", s)
		}
	})

	for _, typ := range []string{"http", "s3"} {
		t.Run(typ, func(t *testing.T) {
			s, err := get(typ).New(t.Context(), pkgsync.ProviderParams{
				SourceName:     "src",
				Name:           "ds",
				Config:         config.Datasource{Name: "ds", Type: typ, Config: map[string]any{"url": "https://example.com"}},
				Dir:            t.TempDir(),
				MetadataFields: []string{"hash"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := s.(*httpsync.HttpDataSynchronizer); !ok {
				t.Errorf("got %T", s)
			}
		})
	}

	for _, typ := range []string{"git", "http", "s3"} {
		t.Run(typ+" wrong config type", func(t *testing.T) {
			_, err := get(typ).New(t.Context(), pkgsync.ProviderParams{Config: "nope"})
			if err == nil || !strings.Contains(err.Error(), "unexpected config type string") {
				t.Fatalf("expected config type error, got %v", err)
			}
		})
	}
}

func TestParseNotSupported(t *testing.T) {
	r, err := providers.Builtins(nil)
	if err != nil {
		t.Fatal(err)
	}
	for typ, field := range map[string]string{"git": "git", "http": "datasources", "s3": "datasources"} {
		p, _ := r.Get(typ)
		_, err := p.Parse([]byte(`{}`))
		exp := `source type "` + typ + `" can't be used in providers, use the source's ` + field + ` field`
		if err == nil || err.Error() != exp {
			t.Errorf("%s: expected %q, got %v", typ, exp, err)
		}
	}
}

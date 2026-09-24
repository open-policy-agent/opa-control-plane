package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/pkg/service"
	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
)

// accessProvider's config selects the behavior of its Synchronizer:
// {"access": "ok"|"denied"|"none"} and optionally {"fail_new": true}.
type accessProvider struct {
	closed *int // counts Close calls
}

type accessConfig struct {
	Access  string `json:"access"`
	FailNew bool   `json:"fail_new"`
}

func (accessProvider) Type() string                  { return "example.access" }
func (accessProvider) ConfigSchema() json.RawMessage { return json.RawMessage(`{}`) }

func (accessProvider) Parse(raw json.RawMessage) (any, error) {
	var cfg accessConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	if cfg.Access == "" {
		return nil, errors.New("access is required")
	}
	return cfg, nil
}

func (p accessProvider) New(_ context.Context, params pkgsync.ProviderParams) (pkgsync.Synchronizer, error) {
	cfg := params.Config.(accessConfig)
	if cfg.FailNew {
		return nil, errors.New("cannot create")
	}
	if cfg.Access == "none" {
		return &noAccessSync{closed: p.closed}, nil
	}
	return &accessSync{cfg: cfg, closed: p.closed}, nil
}

type noAccessSync struct{ closed *int }

func (*noAccessSync) Execute(context.Context) (map[string]any, error) { return nil, nil }
func (s *noAccessSync) Close(context.Context)                         { *s.closed++ }

type accessSync struct {
	cfg    accessConfig
	closed *int
}

func (*accessSync) Execute(context.Context) (map[string]any, error) { return nil, nil }
func (s *accessSync) Close(context.Context)                         { *s.closed++ }

func (s *accessSync) CheckAccess(context.Context) error {
	if s.cfg.Access == "denied" {
		return errors.New("access denied")
	}
	return nil
}

func TestValidateSourceAccessProviders(t *testing.T) {
	var closed int
	reg := pkgsync.NewSourceProviderRegistry()
	if err := reg.Register(accessProvider{closed: &closed}); err != nil {
		t.Fatal(err)
	}
	entry := func(name string, cfg map[string]any) config.Provider {
		return config.Provider{Name: name, Type: "example.access", Config: cfg}
	}
	src := &config.Source{
		Name: "app",
		Providers: config.Providers{
			entry("ok", map[string]any{"access": "ok"}),
			entry("denied", map[string]any{"access": "denied"}),
			entry("unsupported", map[string]any{"access": "none"}),
			entry("invalid", map[string]any{}),
			entry("broken", map[string]any{"access": "ok", "fail_new": true}),
			{Name: "unknown", Type: "nope"},
		},
	}

	t.Run("not checked without the option", func(t *testing.T) {
		if results := service.ValidateSourceAccess(t.Context(), src, nil); len(results) != 0 {
			t.Fatalf("expected no results, got %v", results)
		}
	})

	t.Run("checked with the option", func(t *testing.T) {
		closed = 0
		results := service.ValidateSourceAccess(t.Context(), src, nil, service.WithAccessSourceProviders(reg))

		exp := []service.BindingAccessResult{
			{Type: "example.access", Name: "ok"},
			{Type: "example.access", Name: "denied", Err: &service.Error{Message: "access denied"}},
			// "unsupported" has no access check, so it isn't reported.
			{Type: "example.access", Name: "invalid", Err: &service.Error{Message: `type "example.access": access is required`, UserError: true}},
			{Type: "example.access", Name: "broken", Err: &service.Error{Message: "cannot create"}},
			{Type: "nope", Name: "unknown", Err: &service.Error{Message: `unknown type "nope"`, UserError: true}},
		}
		if diff := cmp.Diff(exp, results); diff != "" {
			t.Errorf("results (-want,+got):\n%s", diff)
		}
		// Every Synchronizer created is closed: ok, denied and unsupported.
		if closed != 3 {
			t.Errorf("expected 3 Close calls, got %d", closed)
		}
	})
}

func TestWithSourceProviders(t *testing.T) {
	reg := pkgsync.NewSourceProviderRegistry()
	if got := service.New().WithSourceProviders(reg).SourceProviders(); got != reg {
		t.Error("expected the given registry")
	}
	if got := service.New().WithSourceProviders(nil).SourceProviders(); got == nil || len(got.Types()) != 0 {
		t.Errorf("expected an empty registry for nil, got %v", got)
	}
}

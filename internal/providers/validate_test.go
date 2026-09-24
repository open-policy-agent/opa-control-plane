package providers_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/providers"
	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
)

// strictProvider accepts only {"param1": "<string>"}.
type strictProvider struct{}

func (strictProvider) Type() string                  { return "example.custom-source" }
func (strictProvider) ConfigSchema() json.RawMessage { return json.RawMessage(`{}`) }
func (strictProvider) New(context.Context, pkgsync.ProviderParams) (pkgsync.Synchronizer, error) {
	return nil, nil
}

func (strictProvider) Parse(raw json.RawMessage) (any, error) {
	var cfg struct {
		Param1 string `json:"param1"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Param1 == "" {
		return nil, errors.New("param1 is required")
	}
	return cfg, nil
}

func TestValidate(t *testing.T) {
	reg := pkgsync.NewSourceProviderRegistry()
	if err := reg.Register(strictProvider{}); err != nil {
		t.Fatal(err)
	}
	valid := config.Provider{Name: "users", Type: "example.custom-source", Config: map[string]any{"param1": "x"}}

	cases := []struct {
		note      string
		reg       *pkgsync.SourceProviderRegistry
		providers []config.Provider
		exp       []string // substrings of the error; empty for valid
	}{
		{note: "no providers", reg: reg},
		{note: "valid", reg: reg, providers: []config.Provider{valid}},
		{note: "valid with path", reg: reg, providers: []config.Provider{{Name: "u", Type: valid.Type, Path: "a/b", Config: valid.Config}}},
		{
			note:      "missing name",
			reg:       reg,
			providers: []config.Provider{{Type: valid.Type, Config: valid.Config}},
			exp:       []string{`source "app": provider #1: name is required`},
		},
		{
			note:      "duplicate name",
			reg:       reg,
			providers: []config.Provider{valid, valid},
			exp:       []string{`source "app": provider "users": duplicate name`},
		},
		{
			note:      "missing type",
			reg:       reg,
			providers: []config.Provider{{Name: "u"}},
			exp:       []string{`provider "u": type is required`},
		},
		{
			note:      "built-in git",
			reg:       reg,
			providers: []config.Provider{{Name: "u", Type: "git"}},
			exp:       []string{`type "git" can't be used in providers, use the source's git field`},
		},
		{
			note:      "built-in http",
			reg:       reg,
			providers: []config.Provider{{Name: "u", Type: "http"}},
			exp:       []string{`type "http" can't be used in providers, use the source's datasources field`},
		},
		{
			note:      "unknown type",
			reg:       reg,
			providers: []config.Provider{{Name: "u", Type: "nope"}},
			exp:       []string{`unknown type "nope"`},
		},
		{
			note:      "nil registry",
			reg:       nil,
			providers: []config.Provider{valid},
			exp:       []string{`unknown type "example.custom-source"`},
		},
		{
			note:      "parse error",
			reg:       reg,
			providers: []config.Provider{{Name: "u", Type: valid.Type, Config: map[string]any{"param1": "x", "extra": 1}}},
			exp:       []string{`type "example.custom-source": json: unknown field "extra"`},
		},
		{
			note:      "no config",
			reg:       reg,
			providers: []config.Provider{{Name: "u", Type: valid.Type}},
			exp:       []string{`param1 is required`},
		},
		{
			note:      "absolute path",
			reg:       reg,
			providers: []config.Provider{{Name: "u", Type: valid.Type, Path: "/etc", Config: valid.Config}},
			exp:       []string{`path "/etc" must be relative`},
		},
		{
			note:      "path escaping the directory",
			reg:       reg,
			providers: []config.Provider{{Name: "u", Type: valid.Type, Path: "a/../../b", Config: valid.Config}},
			exp:       []string{`path "a/../../b" must not contain ".."`},
		},
		{
			note: "all problems reported",
			reg:  reg,
			providers: []config.Provider{
				{Name: "a", Type: "nope"},
				{Name: "b", Type: "git"},
			},
			exp: []string{`provider "a": unknown type "nope"`, `provider "b": type "git"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.note, func(t *testing.T) {
			err := providers.Validate(tc.reg, &config.Source{Name: "app", Providers: tc.providers})
			if len(tc.exp) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			for _, exp := range tc.exp {
				if !strings.Contains(err.Error(), exp) {
					t.Errorf("expected error containing %q, got %q", exp, err)
				}
			}
		})
	}
}

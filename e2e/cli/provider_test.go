// Copyright 2026 The OPA Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
)

// filesProvider is a source provider for E2E tests (type "e2e.files"): its
// entries' configuration says exactly what to produce, e.g.
//
//	providers:
//	  - name: users
//	    type: e2e.files
//	    files:
//	      data.json: '{"alice": ["admin"]}'
//	    metadata: {version: v1}              # returned from Execute
//	    contribution:                        # returned from Contribution
//	      metadata: {example: {version: v1}}
//	      roots: [lazy/remote]
//	      rego_version: 1
type filesProvider struct{}

type filesConfig struct {
	Files        map[string]string      `json:"files"`
	Metadata     map[string]any         `json:"metadata"`
	Contribution *filesContributionSpec `json:"contribution"`
}

type filesContributionSpec struct {
	Metadata    map[string]any `json:"metadata"`
	Roots       []string       `json:"roots"`
	RegoVersion *int           `json:"rego_version"`
}

func (filesProvider) Type() string { return "e2e.files" }

func (filesProvider) ConfigSchema() json.RawMessage {
	return json.RawMessage(`{"type": "object"}`)
}

func (filesProvider) Parse(raw json.RawMessage) (any, error) {
	var cfg filesConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (filesProvider) New(_ context.Context, p pkgsync.ProviderParams) (pkgsync.Synchronizer, error) {
	return &filesSync{cfg: p.Config.(filesConfig), dir: p.Dir}, nil
}

type filesSync struct {
	cfg filesConfig
	dir string
}

func (s *filesSync) Execute(context.Context) (map[string]any, error) {
	for name, content := range s.cfg.Files {
		path := filepath.Join(s.dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return nil, err
		}
	}
	return s.cfg.Metadata, nil
}

func (s *filesSync) Contribution(context.Context) (pkgsync.BundleContribution, error) {
	if s.cfg.Contribution == nil {
		return pkgsync.BundleContribution{}, nil
	}
	return pkgsync.BundleContribution{
		Metadata:    s.cfg.Contribution.Metadata,
		Roots:       s.cfg.Contribution.Roots,
		RegoVersion: s.cfg.Contribution.RegoVersion,
	}, nil
}

func (*filesSync) Close(context.Context) {}

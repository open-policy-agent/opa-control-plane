package providers

import (
	"context"
	"encoding/json"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/gitsync"
	"github.com/open-policy-agent/opa-control-plane/pkg/metrics"
	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
)

// Git provides a source's git repository. ProviderParams.Config must be a
// config.Git; Dir is the repository checkout directory.
type Git struct {
	metrics *metrics.Metrics
}

// NewGit returns the git provider, reporting to m (which may be nil).
func NewGit(m *metrics.Metrics) *Git {
	return &Git{metrics: m}
}

func (*Git) Type() string                  { return TypeGit }
func (*Git) ConfigSchema() json.RawMessage { return builtinSchema }

func (*Git) Parse(json.RawMessage) (any, error) {
	return nil, errParse(TypeGit, "git")
}

func (g *Git) New(_ context.Context, p pkgsync.ProviderParams) (pkgsync.Synchronizer, error) {
	cfg, ok := p.Config.(config.Git)
	if !ok {
		return nil, errConfig(TypeGit, p.Config)
	}
	return gitsync.New(p.Dir, cfg, p.SourceName).
		WithSecretProvider(p.SecretProvider).
		WithMetrics(g.metrics), nil
}

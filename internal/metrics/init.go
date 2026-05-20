package metrics

import (
	"github.com/open-policy-agent/opa-control-plane/internal/config"
)

// Init initializes all metrics collectors with the given configuration.
// Must be called once before any metrics are recorded.
func Init(cfg *config.MetricsConfig) {
	initHTTPMetrics(cfg)
	initGitSyncMetrics(cfg)
	initWorkerMetrics(cfg)
}

func isEnabled(enabled *bool) bool {
	return enabled == nil || *enabled
}

func buckets(configured []float64, defaults []float64) []float64 {
	if len(configured) > 0 {
		return configured
	}
	return defaults
}

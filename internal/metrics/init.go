package metrics

import (
	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/prometheus/client_golang/prometheus"
)

var metricsGatherer prometheus.Gatherer

// Init initializes all metrics collectors with the given configuration.
// Must be called once before any metrics are recorded.
func Init(cfg *config.MetricsConfig, prometheusRegisterer prometheus.Registerer) {
	// Reset all metric vars so re-initialization with a new registry works.
	resetMetrics()

	if g, ok := prometheusRegisterer.(prometheus.Gatherer); ok {
		metricsGatherer = g
	}

	if cfg != nil && !isEnabled(cfg.Enabled) {
		return
	}
	initHTTPMetrics(cfg, prometheusRegisterer)
	initGitSyncMetrics(cfg, prometheusRegisterer)
	initWorkerMetrics(cfg, prometheusRegisterer)
}

func resetMetrics() {
	durationHistogram = nil
	gitSyncCount = nil
	gitSyncDuration = nil
	bundleBuildCount = nil
	bundleBuildDuration = nil
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

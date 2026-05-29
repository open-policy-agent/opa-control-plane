package metrics

import (
	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds all registered Prometheus collectors for the application.
type Metrics struct {
	gatherer            prometheus.Gatherer
	durationHistogram   *prometheus.HistogramVec
	gitSyncCount        *prometheus.CounterVec
	gitSyncDuration     *prometheus.HistogramVec
	bundleBuildCount    *prometheus.CounterVec
	bundleBuildDuration *prometheus.HistogramVec
}

// Init initializes all metrics collectors with the given configuration and returns
// the Metrics instance. Pass the returned value to components that record metrics.
func Init(cfg *config.MetricsConfig, prometheusRegisterer prometheus.Registerer) *Metrics {
	m := &Metrics{}

	if g, ok := prometheusRegisterer.(prometheus.Gatherer); ok {
		m.gatherer = g
	}

	if cfg != nil && !isEnabled(cfg.Enabled) {
		return m
	}
	initHTTPMetrics(m, cfg, prometheusRegisterer)
	initGitSyncMetrics(m, cfg, prometheusRegisterer)
	initWorkerMetrics(m, cfg, prometheusRegisterer)
	return m
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

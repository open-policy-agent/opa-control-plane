// Package metrics defines the Prometheus collectors used by OCP and the logic to register them.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const DefaultNamespace = "ocp"

// Metrics holds all registered Prometheus collectors.
type Metrics struct {
	gatherer            prometheus.Gatherer
	durationHistogram   *prometheus.HistogramVec
	gitSyncCount        *prometheus.CounterVec
	gitSyncDuration     *prometheus.HistogramVec
	bundleBuildCount    *prometheus.CounterVec
	bundleBuildDuration *prometheus.HistogramVec
}

// Options configures collector creation and registration.
type Options struct {
	Registerer prometheus.Registerer
	Namespace  string

	// HTTP request metrics.
	HTTPEnabled                *bool
	HTTPRequestDurationEnabled *bool
	HTTPRequestDurationBuckets []float64

	// Git sync metrics.
	GitSyncEnabled         *bool
	GitSyncCountEnabled    *bool
	GitSyncDurationEnabled *bool
	GitSyncDurationBuckets []float64

	// Worker (bundle build) metrics.
	WorkerEnabled              *bool
	BundleBuildCountEnabled    *bool
	BundleBuildDurationEnabled *bool
	BundleBuildDurationBuckets []float64
}

// New builds and registers all enabled collectors against opts.Registerer and
// returns the Metrics instance.
func New(opts Options) *Metrics {
	m := &Metrics{}

	if g, ok := opts.Registerer.(prometheus.Gatherer); ok {
		m.gatherer = g
	}

	if opts.Namespace == "" {
		opts.Namespace = DefaultNamespace
	}

	initHTTPMetrics(m, opts)
	initGitSyncMetrics(m, opts)
	initWorkerMetrics(m, opts)
	return m
}

func (m *Metrics) Handler() http.Handler {
	if m != nil && m.gatherer != nil {
		return promhttp.HandlerFor(m.gatherer, promhttp.HandlerOpts{})
	}
	return promhttp.Handler()
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

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var defaultWorkerBuckets = []float64{0.1, 0.2, 0.5, 1, 1.5, 2, 5, 10, 30, 60}

func initWorkerMetrics(m *Metrics, opts Options) {
	if !isEnabled(opts.WorkerEnabled) {
		return
	}

	if isEnabled(opts.BundleBuildCountEnabled) {
		m.bundleBuildCount = promauto.With(opts.Registerer).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: opts.Namespace,
				Name:      "bundle_build_count_total",
				Help:      "Number of times a bundle build has been performed and its state",
			},
			[]string{"bundle", "state"},
		)
	}

	if !isEnabled(opts.BundleBuildDurationEnabled) {
		return
	}

	m.bundleBuildDuration = promauto.With(opts.Registerer).NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: opts.Namespace,
			Name:      "bundle_build_duration_seconds",
			Help:      "Bundle build duration in seconds",
			Buckets:   buckets(opts.BundleBuildDurationBuckets, defaultWorkerBuckets),
		},
		[]string{"bundle"},
	)
}

func (m *Metrics) BundleBuildFailed(bundle string, state string) {
	if m == nil || m.bundleBuildCount == nil {
		return
	}
	m.bundleBuildCount.WithLabelValues(bundle, state).Inc()
}

func (m *Metrics) BundleBuildSucceeded(bundle string, state string, startTime time.Time) {
	if m == nil || m.bundleBuildCount == nil {
		return
	}
	m.bundleBuildCount.WithLabelValues(bundle, state).Inc()
	if m.bundleBuildDuration != nil {
		m.bundleBuildDuration.WithLabelValues(bundle).Observe(float64(time.Since(startTime).Seconds()))
	}
}

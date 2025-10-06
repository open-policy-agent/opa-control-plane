package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	bundleBuildCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ocp_bundle_build_count_total",
			Help: "Number of times a bundle build has been performed and its state",
		},
		[]string{"bundle", "state"},
	)

	bundleBuildDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ocp_bundle_build_duration_seconds",
			Help:    "Bundle build duration in seconds",
			Buckets: []float64{0.1, 0.2, 0.5, 1, 1.5, 2, 5, 10, 30, 60},
		},
		[]string{"bundle"},
	)
)

func BundleBuildFailed(bundle string, state string) {
	bundleBuildCount.WithLabelValues(bundle, state).Inc()
}

func BundleBuildSucceeded(bundle string, state string, startTime time.Time) {
	bundleBuildCount.WithLabelValues(bundle, state).Inc()
	bundleBuildDuration.WithLabelValues(bundle).Observe(float64(time.Since(startTime).Seconds()))
}

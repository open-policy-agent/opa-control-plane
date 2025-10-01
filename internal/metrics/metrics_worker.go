package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	BundleBuildFailed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ocp_bundle_build_failed",
			Help: "Number of times a bundle has failed to build",
		},
		[]string{"bundle", "error_type"},
	)

	BundleBuildCount = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ocp_bundle_build_count",
			Help: "Total number of times a bundle has been built",
		},
	)

	BundleBuildDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ocp_bundle_build_duration_seconds",
			Help:    "Bundle build duration in seconds",
			Buckets: []float64{0.1, 0.2, 0.5, 1, 1.5, 2, 5, 10, 30, 60},
		},
		[]string{"bundle"},
	)

	LastBundleBuildStart = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ocp_last_bundle_build_start_timestamp",
			Help: "Unix timestamp of when the last bundle build started",
		},
		[]string{"bundle"},
	)

	LastBundleBuildEnd = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ocp_last_bundle_build_end_timestamp",
			Help: "Unix timestamp of when the last bundle build ended",
		},
		[]string{"bundle"},
	)
)

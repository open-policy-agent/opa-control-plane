package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	GitSyncCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ocp_git_sync_count_total",
			Help: "Number of times a git sync has been performed and its state",
		},
		[]string{"source", "repo", "state"},
	)

	GitSyncDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ocp_git_sync_duration_seconds",
			Help:    "Git sync duration in seconds",
			Buckets: []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5, 2, 5, 10, 30, 60},
		},
		[]string{"source", "repo"},
	)
)

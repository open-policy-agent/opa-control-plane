package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	GitSyncFailed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ocp_git_sync_failed_total",
			Help: "Total number of failed Git sync operations",
		},
		[]string{"source"},
	)

	GitSyncCount = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ocp_git_sync_count_total",
			Help: "Total number of Git sync operations",
		},
	)

	GitSyncDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ocp_git_sync_duration_seconds",
			Help:    "Git sync duration in seconds",
			Buckets: []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5, 2, 5, 10, 30, 60},
		},
		[]string{"source", "repo"},
	)

	LastGitSyncStart = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ocp_last_git_sync_start_timestamp",
			Help: "Unix timestamp of when the last git sync started",
		},
		[]string{"source", "repo"},
	)

	LastGitSyncEnd = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ocp_last_git_sync_end_timestamp",
			Help: "Unix timestamp of when the last git sync ended",
		},
		[]string{"source", "repo"},
	)
)

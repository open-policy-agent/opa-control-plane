package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var defaultGitSyncBuckets = []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5, 2, 5, 10, 30, 60}

func initGitSyncMetrics(m *Metrics, opts Options) {
	if !isEnabled(opts.GitSyncEnabled) {
		return
	}

	if isEnabled(opts.GitSyncCountEnabled) {
		m.gitSyncCount = promauto.With(opts.Registerer).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: opts.Namespace,
				Name:      "git_sync_count_total",
				Help:      "Number of times a git sync has been performed and its state",
			},
			[]string{"source", "repo", "state"},
		)

		m.gitSyncServerError = promauto.With(opts.Registerer).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: opts.Namespace,
				Name:      "git_sync_server_error_total",
				Help:      "Number of git syncs that failed due to a non-user (server/transient) error",
			},
			[]string{"source", "repo"},
		)
	}

	if !isEnabled(opts.GitSyncDurationEnabled) {
		return
	}

	m.gitSyncDuration = promauto.With(opts.Registerer).NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: opts.Namespace,
			Name:      "git_sync_duration_seconds",
			Help:      "Git sync duration in seconds",
			Buckets:   buckets(opts.GitSyncDurationBuckets, defaultGitSyncBuckets),
		},
		[]string{"source", "repo"},
	)
}

func (m *Metrics) GitSyncFailed(source string, repo string) {
	if m == nil || m.gitSyncCount == nil {
		return
	}
	m.gitSyncCount.WithLabelValues(source, repo, "FAILED").Inc()
}

// GitSyncServerError records a git sync failure caused by a non-user
// (server/transient) error, as opposed to a user misconfiguration. This is a
// subset of the failures counted by GitSyncFailed.
func (m *Metrics) GitSyncServerError(source string, repo string) {
	if m == nil || m.gitSyncServerError == nil {
		return
	}
	m.gitSyncServerError.WithLabelValues(source, repo).Inc()
}

func (m *Metrics) GitSyncSucceeded(source string, repo string, startTime time.Time) {
	if m == nil || m.gitSyncCount == nil {
		return
	}
	m.gitSyncCount.WithLabelValues(source, repo, "SUCCESS").Inc()
	if m.gitSyncDuration != nil {
		m.gitSyncDuration.WithLabelValues(source, repo).Observe(float64(time.Since(startTime).Seconds()))
	}
}

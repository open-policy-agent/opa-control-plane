package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
)

var (
	gitSyncCount    *prometheus.CounterVec
	gitSyncDuration *prometheus.HistogramVec

	defaultGitSyncBuckets = []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5, 2, 5, 10, 30, 60}
)

func initGitSyncMetrics(cfg *config.MetricsConfig, prometheusRegisterer prometheus.Registerer) {
	var gcfg *config.GitSyncMetrics
	if cfg != nil {
		gcfg = cfg.GitSync
	}

	if gcfg != nil && !isEnabled(gcfg.Enabled) {
		return
	}

	if gcfg == nil || isEnabled(gcfg.GetCountEnabled()) {
		gitSyncCount = promauto.With(prometheusRegisterer).NewCounterVec(
			prometheus.CounterOpts{
				Name: "ocp_git_sync_count_total",
				Help: "Number of times a git sync has been performed and its state",
			},
			[]string{"source", "repo", "state"},
		)
	}

	var hcfg *config.HistogramConfig
	if gcfg != nil {
		hcfg = gcfg.GitSyncDuration
	}

	if hcfg != nil && !isEnabled(hcfg.Enabled) {
		return
	}

	gitSyncDuration = promauto.With(prometheusRegisterer).NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ocp_git_sync_duration_seconds",
			Help:    "Git sync duration in seconds",
			Buckets: buckets(hcfg.GetBuckets(), defaultGitSyncBuckets),
		},
		[]string{"source", "repo"},
	)
}

func GitSyncFailed(source string, repo string) {
	if gitSyncCount != nil {
		gitSyncCount.WithLabelValues(source, repo, "FAILED").Inc()
	}
}

func GitSyncSucceeded(source string, repo string, startTime time.Time) {
	if gitSyncCount != nil {
		gitSyncCount.WithLabelValues(source, repo, "SUCCESS").Inc()
	}
	if gitSyncDuration != nil {
		gitSyncDuration.WithLabelValues(source, repo).Observe(float64(time.Since(startTime).Seconds()))
	}
}

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
)

var (
	bundleBuildCount    *prometheus.CounterVec
	bundleBuildDuration *prometheus.HistogramVec

	defaultWorkerBuckets = []float64{0.1, 0.2, 0.5, 1, 1.5, 2, 5, 10, 30, 60}
)

func initWorkerMetrics(cfg *config.MetricsConfig, prometheusRegisterer prometheus.Registerer) {
	var wcfg *config.WorkerMetrics
	if cfg != nil {
		wcfg = cfg.Worker
	}

	if wcfg != nil && !isEnabled(wcfg.Enabled) {
		return
	}

	if wcfg == nil || isEnabled(wcfg.GetCountEnabled()) {
		bundleBuildCount = promauto.With(prometheusRegisterer).NewCounterVec(
			prometheus.CounterOpts{
				Name: "ocp_bundle_build_count_total",
				Help: "Number of times a bundle build has been performed and its state",
			},
			[]string{"bundle", "state"},
		)
	}

	var hcfg *config.HistogramConfig
	if wcfg != nil {
		hcfg = wcfg.BundleBuildDuration
	}

	if hcfg != nil && !isEnabled(hcfg.Enabled) {
		return
	}

	bundleBuildDuration = promauto.With(prometheusRegisterer).NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ocp_bundle_build_duration_seconds",
			Help:    "Bundle build duration in seconds",
			Buckets: buckets(hcfg.GetBuckets(), defaultWorkerBuckets),
		},
		[]string{"bundle"},
	)
}

func BundleBuildFailed(bundle string, state string) {
	if bundleBuildCount != nil {
		bundleBuildCount.WithLabelValues(bundle, state).Inc()
	}
}

func BundleBuildSucceeded(bundle string, state string, startTime time.Time) {
	if bundleBuildCount != nil {
		bundleBuildCount.WithLabelValues(bundle, state).Inc()
	}
	if bundleBuildDuration != nil {
		bundleBuildDuration.WithLabelValues(bundle).Observe(float64(time.Since(startTime).Seconds()))
	}
}

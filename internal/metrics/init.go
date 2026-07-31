package metrics

import (
	"github.com/open-policy-agent/opa-control-plane/internal/config"
	pkgmetrics "github.com/open-policy-agent/opa-control-plane/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func Init(cfg *config.MetricsConfig, reg prometheus.Registerer) *pkgmetrics.Metrics {
	opts := pkgmetrics.Options{
		Registerer: reg,
		Namespace:  pkgmetrics.DefaultNamespace, // preserve existing OCP metric names
	}

	if cfg == nil {
		return pkgmetrics.New(opts)
	}

	if cfg.Enabled != nil && !*cfg.Enabled {
		disabled := false
		opts.HTTPEnabled = &disabled
		opts.GitSyncEnabled = &disabled
		opts.WorkerEnabled = &disabled
		return pkgmetrics.New(opts)
	}

	if cfg.HTTP != nil {
		opts.HTTPEnabled = cfg.HTTP.Enabled
		if cfg.HTTP.RequestDuration != nil {
			opts.HTTPRequestDurationEnabled = cfg.HTTP.RequestDuration.Enabled
			opts.HTTPRequestDurationBuckets = cfg.HTTP.RequestDuration.GetBuckets()
		}
	}

	if cfg.GitSync != nil {
		opts.GitSyncEnabled = cfg.GitSync.Enabled
		opts.GitSyncCountEnabled = cfg.GitSync.GetCountEnabled()
		if cfg.GitSync.GitSyncDuration != nil {
			opts.GitSyncDurationEnabled = cfg.GitSync.GitSyncDuration.Enabled
			opts.GitSyncDurationBuckets = cfg.GitSync.GitSyncDuration.GetBuckets()
		}
	}

	if cfg.Worker != nil {
		opts.WorkerEnabled = cfg.Worker.Enabled
		opts.BundleBuildCountEnabled = cfg.Worker.GetCountEnabled()
		if cfg.Worker.BundleBuildDuration != nil {
			opts.BundleBuildDurationEnabled = cfg.Worker.BundleBuildDuration.Enabled
			opts.BundleBuildDurationBuckets = cfg.Worker.BundleBuildDuration.GetBuckets()
		}
	}

	return pkgmetrics.New(opts)
}

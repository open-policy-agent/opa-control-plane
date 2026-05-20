package config

import (
	"testing"
)

func TestMetricsConfig(t *testing.T) {
	input := `
metrics:
  gitsync:
    git_sync_duration:
      buckets_seconds: [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5]
    git_sync_count:
      enabled: true
  http:
    request_duration:
      buckets_seconds: [0.1, 0.3, 1.2, 5.0]
  worker:
    bundle_build_duration:
      enabled: false
    bundle_build_count:
      enabled: false
`

	cfg, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Error parsing config: %v", err)
	}

	if cfg.Metrics == nil {
		t.Fatal("Metrics config is nil")
	}

	// Test HTTP metrics
	if cfg.Metrics.HTTP == nil || cfg.Metrics.HTTP.RequestDuration == nil {
		t.Fatal("HTTP RequestDuration config is missing")
	}
	if len(cfg.Metrics.HTTP.RequestDuration.BucketsSeconds) != 4 {
		t.Fatalf("Expected 4 HTTP buckets, got %d", len(cfg.Metrics.HTTP.RequestDuration.BucketsSeconds))
	}
	if cfg.Metrics.HTTP.RequestDuration.BucketsSeconds[0] != 0.1 {
		t.Fatalf("Expected first HTTP bucket 0.1, got %v", cfg.Metrics.HTTP.RequestDuration.BucketsSeconds[0])
	}

	// Test GitSync metrics
	if cfg.Metrics.GitSync == nil || cfg.Metrics.GitSync.GitSyncDuration == nil {
		t.Fatal("GitSync GitSyncDuration config is missing")
	}
	if len(cfg.Metrics.GitSync.GitSyncDuration.BucketsSeconds) != 10 {
		t.Fatalf("Expected 10 GitSync buckets, got %d", len(cfg.Metrics.GitSync.GitSyncDuration.BucketsSeconds))
	}
	if cfg.Metrics.GitSync.GitSyncCount == nil || cfg.Metrics.GitSync.GitSyncCount.Enabled == nil || !*cfg.Metrics.GitSync.GitSyncCount.Enabled {
		t.Fatal("GitSyncCount should be explicitly enabled")
	}

	// Test Worker metrics
	if cfg.Metrics.Worker == nil {
		t.Fatal("Worker config is missing")
	}
	if cfg.Metrics.Worker.BundleBuildDuration == nil || cfg.Metrics.Worker.BundleBuildDuration.Enabled == nil || *cfg.Metrics.Worker.BundleBuildDuration.Enabled {
		t.Fatal("BundleBuildDuration should be disabled")
	}
	if cfg.Metrics.Worker.BundleBuildCount == nil || cfg.Metrics.Worker.BundleBuildCount.Enabled == nil || *cfg.Metrics.Worker.BundleBuildCount.Enabled {
		t.Fatal("BundleBuildCount should be disabled")
	}
}

func TestMetricsConfigDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`{}`))
	if err != nil {
		t.Fatalf("Error parsing config: %v", err)
	}

	// With no metrics key, Metrics should be nil (all defaults apply)
	if cfg.Metrics != nil {
		t.Fatal("Metrics should be nil with empty config")
	}
}

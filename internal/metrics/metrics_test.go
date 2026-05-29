package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
)

func boolPtr(b bool) *bool { return &b }

// TestNilMetricsSafe verifies the nil-receiver contract: components that receive
// no metrics (e.g. in tests) must not panic.
func TestNilMetricsSafe(t *testing.T) {
	var m *Metrics
	m.GitSyncFailed("src", "repo")
	m.GitSyncSucceeded("src", "repo", time.Now())
	m.BundleBuildFailed("b", "FAILED")
	m.BundleBuildSucceeded("b", "SUCCESS", time.Now())
	if m.Handler() == nil {
		t.Error("Handler() on nil Metrics must return a non-nil fallback")
	}
}

func TestDisable(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.MetricsConfig
		// fields expected to be nil after Init
		wantNil []func(*Metrics) bool
	}{
		{
			name: "global",
			cfg:  &config.MetricsConfig{Enabled: boolPtr(false)},
			wantNil: []func(*Metrics) bool{
				func(m *Metrics) bool { return m.durationHistogram == nil },
				func(m *Metrics) bool { return m.gitSyncCount == nil },
				func(m *Metrics) bool { return m.bundleBuildCount == nil },
			},
		},
		{
			name: "gitsync subsystem",
			cfg:  &config.MetricsConfig{GitSync: &config.GitSyncMetrics{Enabled: boolPtr(false)}},
			wantNil: []func(*Metrics) bool{
				func(m *Metrics) bool { return m.gitSyncCount == nil },
				func(m *Metrics) bool { return m.gitSyncDuration == nil },
				func(m *Metrics) bool { return m.durationHistogram != nil }, // others unaffected
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := Init(tc.cfg, prometheus.NewRegistry())
			for i, check := range tc.wantNil {
				if !check(m) {
					t.Errorf("check %d failed", i)
				}
			}
		})
	}
}

func TestGitSyncRecording(t *testing.T) {
	m := Init(nil, prometheus.NewRegistry())

	m.GitSyncFailed("s1", "repo1")
	m.GitSyncFailed("s1", "repo1")
	m.GitSyncSucceeded("s1", "repo1", time.Now())

	if got := testutil.ToFloat64(m.gitSyncCount.WithLabelValues("s1", "repo1", "FAILED")); got != 2 {
		t.Errorf("FAILED count: want 2, got %v", got)
	}
	if got := testutil.ToFloat64(m.gitSyncCount.WithLabelValues("s1", "repo1", "SUCCESS")); got != 1 {
		t.Errorf("SUCCESS count: want 1, got %v", got)
	}
}

package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
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
		opts Options
		// fields expected to be nil after New
		wantNil []func(*Metrics) bool
	}{
		{
			name: "all subsystems",
			opts: Options{
				HTTPEnabled:    boolPtr(false),
				GitSyncEnabled: boolPtr(false),
				WorkerEnabled:  boolPtr(false),
			},
			wantNil: []func(*Metrics) bool{
				func(m *Metrics) bool { return m.durationHistogram == nil },
				func(m *Metrics) bool { return m.gitSyncCount == nil },
				func(m *Metrics) bool { return m.bundleBuildCount == nil },
			},
		},
		{
			name: "gitsync subsystem",
			opts: Options{GitSyncEnabled: boolPtr(false)},
			wantNil: []func(*Metrics) bool{
				func(m *Metrics) bool { return m.gitSyncCount == nil },
				func(m *Metrics) bool { return m.gitSyncDuration == nil },
				func(m *Metrics) bool { return m.durationHistogram != nil }, // others unaffected
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Registerer = prometheus.NewRegistry()
			m := New(tc.opts)
			for i, check := range tc.wantNil {
				if !check(m) {
					t.Errorf("check %d failed", i)
				}
			}
		})
	}
}

func TestGitSyncRecording(t *testing.T) {
	m := New(Options{Registerer: prometheus.NewRegistry()})

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

// TestNamespace verifies the fully-qualified metric names are derived from the
// configured Namespace prefix: the default preserves the historical "ocp_"
// names, and a custom prefix remaps them.
func TestNamespace(t *testing.T) {
	cases := []struct {
		name      string
		namespace string
		want      []string
	}{
		{
			name:      "default",
			namespace: "",
			want: []string{
				"ocp_git_sync_count_total",
				"ocp_git_sync_duration_seconds",
			},
		},
		{
			name:      "custom",
			namespace: "build_worker",
			want: []string{
				"build_worker_git_sync_count_total",
				"build_worker_git_sync_duration_seconds",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			m := New(Options{Registerer: reg, Namespace: tc.namespace})

			// Observe once so the vec metric families are emitted by Gather.
			m.GitSyncSucceeded("s1", "repo1", time.Now())

			mfs, err := reg.Gather()
			if err != nil {
				t.Fatalf("gather: %v", err)
			}
			got := make(map[string]bool, len(mfs))
			for _, mf := range mfs {
				got[mf.GetName()] = true
			}
			for _, name := range tc.want {
				if !got[name] {
					t.Errorf("expected metric family %q, got %v", name, got)
				}
			}
		})
	}
}

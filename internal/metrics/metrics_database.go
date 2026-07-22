package metrics

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
)

var defaultDatabaseQueryBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

func initDatabaseMetrics(m *Metrics, cfg *config.MetricsConfig, prometheusRegisterer prometheus.Registerer) {
	var dcfg *config.DatabaseMetrics
	if cfg != nil {
		dcfg = cfg.Database
	}

	if dcfg != nil && !isEnabled(dcfg.Enabled) {
		return
	}

	if dcfg == nil || isEnabled(dcfg.GetCountEnabled()) {
		m.databaseQueryCount = promauto.With(prometheusRegisterer).NewCounterVec(
			prometheus.CounterOpts{
				Name: "ocp_database_query_count_total",
				Help: "Number of database queries performed and their outcome",
			},
			[]string{"operation", "state"},
		)
	}

	var hcfg *config.HistogramConfig
	if dcfg != nil {
		hcfg = dcfg.DatabaseQueryDuration
	}

	if hcfg != nil && !isEnabled(hcfg.Enabled) {
		return
	}

	m.databaseQueryDuration = promauto.With(prometheusRegisterer).NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ocp_database_query_duration_seconds",
			Help:    "Database query duration in seconds",
			Buckets: buckets(hcfg.GetBuckets(), defaultDatabaseQueryBuckets),
		},
		[]string{"operation"},
	)
}

func (m *Metrics) DatabaseQueryFailed(operation string) {
	if m == nil || m.databaseQueryCount == nil {
		return
	}
	m.databaseQueryCount.WithLabelValues(operation, "FAILED").Inc()
}

func (m *Metrics) DatabaseQuerySucceeded(operation string, startTime time.Time) {
	if m == nil || m.databaseQueryCount == nil {
		return
	}
	m.databaseQueryCount.WithLabelValues(operation, "SUCCESS").Inc()
	if m.databaseQueryDuration != nil {
		m.databaseQueryDuration.WithLabelValues(operation).Observe(float64(time.Since(startTime).Seconds()))
	}
}

// DatabaseOperation extracts a coarse operation label (e.g. "select",
// "insert") from a SQL statement's first keyword, for use as the "operation"
// label above. Unrecognized or multi-statement input all collapse to
// "other" so the label set stays bounded regardless of query text.
func DatabaseOperation(sql string) string {
	knownOperations := map[string]bool{
		"select": true, "insert": true, "update": true, "delete": true,
		"begin": true, "commit": true, "rollback": true, "savepoint": true,
		"release": true, "pragma": true, "create": true, "alter": true, "drop": true,
	}

	fields := strings.Fields(sql)
	if len(fields) == 0 {
		return "other"
	}
	op := strings.ToLower(fields[0])
	if knownOperations[op] {
		return op
	}
	return "other"
}

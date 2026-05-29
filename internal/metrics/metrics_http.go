package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
)

var defaultHTTPBuckets = []float64{
	1e-6, // 1 microsecond
	5e-6,
	1e-5,
	5e-5,
	1e-4,
	5e-4,
	1e-3, // 1 millisecond
	0.01,
	0.1,
	1, // 1 second
}

func initHTTPMetrics(m *Metrics, cfg *config.MetricsConfig, prometheusRegisterer prometheus.Registerer) {
	if cfg != nil && cfg.HTTP != nil && !isEnabled(cfg.HTTP.Enabled) {
		return
	}

	var hcfg *config.HistogramConfig
	if cfg != nil && cfg.HTTP != nil {
		hcfg = cfg.HTTP.RequestDuration
	}

	if hcfg != nil && !isEnabled(hcfg.Enabled) {
		return
	}

	m.durationHistogram = promauto.With(prometheusRegisterer).NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "A histogram of duration for requests.",
			Buckets: buckets(hcfg.GetBuckets(), defaultHTTPBuckets),
		},
		[]string{"code", "handler", "method"},
	)
}

func (m *Metrics) InstrumentHandler(label string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if m == nil || m.durationHistogram == nil {
			return next
		}
		durationCollector := m.durationHistogram.MustCurryWith(prometheus.Labels{"handler": label})
		return promhttp.InstrumentHandlerDuration(durationCollector, next)
	}
}

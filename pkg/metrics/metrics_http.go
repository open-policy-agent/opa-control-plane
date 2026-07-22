package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

func initHTTPMetrics(m *Metrics, opts Options) {
	if !isEnabled(opts.HTTPEnabled) {
		return
	}

	if !isEnabled(opts.HTTPRequestDurationEnabled) {
		return
	}

	m.durationHistogram = promauto.With(opts.Registerer).NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: opts.Namespace,
			Name:      "http_request_duration_seconds",
			Help:      "A histogram of duration for requests.",
			Buckets:   buckets(opts.HTTPRequestDurationBuckets, defaultHTTPBuckets),
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

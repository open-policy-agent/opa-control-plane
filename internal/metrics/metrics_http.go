package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	durationHistogram = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "http_request_duration_seconds",
			Help: "A histogram of duration for requests.",
			Buckets: []float64{
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
			},
		},
		[]string{"code", "handler", "method"},
	)
)

func InstrumentHandler(label string) func(http.Handler) http.Handler {
	durationCollector := durationHistogram.MustCurryWith(prometheus.Labels{"handler": label})
	return func(next http.Handler) http.Handler {
		return promhttp.InstrumentHandlerDuration(durationCollector, next)
	}
}

package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func Handler() http.Handler {
	if metricsGatherer != nil {
		return promhttp.HandlerFor(metricsGatherer, promhttp.HandlerOpts{})
	}
	return promhttp.Handler()
}

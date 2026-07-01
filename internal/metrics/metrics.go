package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func (m *Metrics) Handler() http.Handler {
	if m != nil && m.gatherer != nil {
		return promhttp.HandlerFor(m.gatherer, promhttp.HandlerOpts{})
	}
	return promhttp.Handler()
}

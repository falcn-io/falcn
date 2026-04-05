package proxy

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	proxyRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "falcn",
		Subsystem: "proxy",
		Name:      "requests_total",
		Help:      "Total number of proxy requests by registry and decision.",
	}, []string{"registry", "decision"})

	proxyPackagesScanned = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "falcn",
		Subsystem: "proxy",
		Name:      "packages_scanned_total",
		Help:      "Total number of packages scanned.",
	})

	proxyPackagesBlocked = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "falcn",
		Subsystem: "proxy",
		Name:      "packages_blocked_total",
		Help:      "Total number of packages blocked.",
	})

	proxyPackagesWarned = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "falcn",
		Subsystem: "proxy",
		Name:      "packages_warned_total",
		Help:      "Total number of packages with warnings.",
	})

	proxyScanDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "falcn",
		Subsystem: "proxy",
		Name:      "scan_duration_seconds",
		Help:      "Histogram of package scan durations.",
		Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
	})

	proxyCacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "falcn",
		Subsystem: "proxy",
		Name:      "cache_hits_total",
		Help:      "Total cache hits for scan results.",
	})

	proxyCacheMisses = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "falcn",
		Subsystem: "proxy",
		Name:      "cache_misses_total",
		Help:      "Total cache misses for scan results.",
	})

	proxyThreatsByType = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "falcn",
		Subsystem: "proxy",
		Name:      "threats_detected_total",
		Help:      "Total threats detected by type and severity.",
	}, []string{"type", "severity"})

	proxyUpstreamLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "falcn",
		Subsystem: "proxy",
		Name:      "upstream_latency_seconds",
		Help:      "Histogram of upstream registry response times.",
		Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"registry"})
)

// MetricsHandler returns the Prometheus metrics HTTP handler.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

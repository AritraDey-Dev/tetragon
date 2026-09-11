// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metricsconfig

import (
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

func initResourcesMetrics(registry *prometheus.Registry) {
	// register common third-party collectors
	registry.MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(
			collectors.GoRuntimeMetricsRule{Matcher: regexp.MustCompile(`^/sched/latencies:seconds`)},
		)))
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

func initAllResourcesMetrics(registry *prometheus.Registry) {
	initResourcesMetrics(registry)
}

func InitResourcesMetricsForDocs(registry *prometheus.Registry) {
	initResourcesMetrics(registry)
}

func InitEventsMetrics(registry *prometheus.Registry) {
	eventsMetrics := EnableEventsMetrics(registry)
	eventsMetrics.Init()
}

func InitHealthMetrics(registry *prometheus.Registry) {
	healthMetrics := EnableHealthMetrics(registry)
	healthMetrics.Init()
	initAllResourcesMetrics(registry)
}

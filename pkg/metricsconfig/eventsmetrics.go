// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metricsconfig

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/cilium/tetragon/pkg/metrics/syscallmetrics"
)

var (
	eventsMetrics     metrics.Group
	eventsMetricsOnce sync.Once
)

// GetEventsGroup returns the events metrics group, creating and populating it
// on first use.
//
// The group is unconstrained: events metrics carry per-workload labels, so
// their cardinality depends on what is running on the node and cannot be known
// upfront.
func GetEventsGroup() metrics.Group {
	eventsMetricsOnce.Do(func() {
		eventsMetrics = metrics.NewMetricsGroup(false)
		registerEventsMetrics(eventsMetrics)
	})
	return eventsMetrics
}

// EnableEventsMetrics registers the events metrics group in the given registry
// and returns it.
func EnableEventsMetrics(registry *prometheus.Registry) metrics.Group {
	eventsMetrics := GetEventsGroup()
	registry.MustRegister(eventsMetrics)
	return eventsMetrics
}

// NOTE: Registration happens once, from GetEventsGroup. Unlike
// registerHealthMetrics this is not safe to call repeatedly, since registering
// the same collector in a group twice is an error.
func registerEventsMetrics(group metrics.Group) {
	// event metrics
	eventmetrics.RegisterEventsMetrics(group)
	// syscall metrics
	syscallmetrics.RegisterMetrics(group)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metricsconfig

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

// EventsMetricsPath is where the events metrics group is served. Health and
// resource metrics stay on /metrics, so the two can be scraped, relabelled and
// retained independently.
const EventsMetricsPath = "/metrics/events"

var (
	registry     *prometheus.Registry
	registryOnce sync.Once

	eventsRegistry     *prometheus.Registry
	eventsRegistryOnce sync.Once
)

func GetRegistry() *prometheus.Registry {
	registryOnce.Do(func() {
		registry = prometheus.NewRegistry()
	})
	return registry
}

// GetEventsRegistry returns the registry backing EventsMetricsPath. It is
// separate from the root registry so that events metrics, whose cardinality
// depends on the workloads running on the node, are not mixed into the health
// metrics scrape.
func GetEventsRegistry() *prometheus.Registry {
	eventsRegistryOnce.Do(func() {
		eventsRegistry = prometheus.NewRegistry()
	})
	return eventsRegistry
}

// newMetricsServer builds the metrics server and binds its listener. Binding is
// separate from serving so that callers observe bind errors synchronously, and
// so tests can learn the address that was actually bound (e.g. when asking for
// port 0).
func newMetricsServer(address string) (*http.Server, net.Listener, error) {
	reg := GetRegistry()
	eventsReg := GetEventsRegistry()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	// Registered unconditionally: the server starts before metrics are
	// initialized, and the endpoint simply returns nothing while the events
	// group is not enabled.
	mux.Handle(EventsMetricsPath, promhttp.HandlerFor(eventsReg, promhttp.HandlerOpts{Registry: eventsReg}))

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, nil, err
	}

	return &http.Server{Handler: mux}, listener, nil
}

// serve starts serving on the already-bound listener in a background
// goroutine and returns a stop function. stop gracefully shuts the server down
// and blocks until the serving goroutine has returned, so callers can rely on
// the server being fully stopped once stop returns. stop is safe to call
// multiple times; typically it is deferred right after a successful
// EnableMetrics.
func serve(server *http.Server, listener net.Listener) (stop func()) {
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.GetLogger().Error("Metrics server exited unexpectedly", logfields.Error, err)
		}
	})

	var stopOnce sync.Once
	return func() {
		stopOnce.Do(func() {
			if err := server.Shutdown(context.Background()); err != nil {
				logger.GetLogger().Error("Failed to shutdown metrics server", logfields.Error, err)
			}
			wg.Wait()
			logger.GetLogger().Info("Metrics server stopped", "addr", listener.Addr())
		})
	}
}

// EnableMetrics starts a Prometheus metrics HTTP server on the given address.
// It binds synchronously and returns any bind error to the caller. On success
// it returns a stop function that gracefully shuts the server down and waits
// for it to finish; callers should defer stop() so both the signal and the
// error paths stop the server.
func EnableMetrics(address string) (stop func(), err error) {
	server, listener, err := newMetricsServer(address)
	if err != nil {
		return nil, err
	}

	logger.GetLogger().Info("Starting metrics server", "addr", listener.Addr())
	return serve(server, listener), nil
}

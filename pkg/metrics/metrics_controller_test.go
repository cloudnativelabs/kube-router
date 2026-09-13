package metrics

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
)

// gatherSyncMetrics returns a throwaway registry holding the two sync collectors, so that each test
// observes exposition the way Prometheus would rather than reading the child values back
func gatherSyncMetrics(t *testing.T) *prometheus.Registry {
	t.Helper()
	ControllerSyncLastSuccess.Reset()
	ControllerSyncFailures.Reset()

	registry := prometheus.NewRegistry()
	registry.MustRegister(ControllerSyncLastSuccess)
	registry.MustRegister(ControllerSyncFailures)
	return registry
}

func TestRecordSyncResult(t *testing.T) {
	t.Run("failure before any success still exposes a last success series", func(t *testing.T) {
		registry := gatherSyncMetrics(t)

		RecordSyncResult(healthcheck.NetworkRoutesController, errors.New("bgp peer unreachable"))

		// Without this series the staleness alert matches an empty vector and stays silent forever
		expected := `
# HELP kube_router_controller_sync_last_success Unix timestamp of the last fully successful sync, by controller
# TYPE kube_router_controller_sync_last_success gauge
kube_router_controller_sync_last_success{controller="NetworkRoutesController"} 0
`
		require.NoError(t, testutil.GatherAndCompare(registry, strings.NewReader(expected),
			"kube_router_controller_sync_last_success"))
		assert.Equal(t, float64(1), testutil.ToFloat64(
			ControllerSyncFailures.WithLabelValues("NetworkRoutesController")))
	})

	t.Run("success before any failure still exposes a failure series", func(t *testing.T) {
		registry := gatherSyncMetrics(t)

		RecordSyncResult(healthcheck.NetworkPolicyController, nil)

		expected := `
# HELP kube_router_controller_sync_failures_total Total count of sync attempts that did not complete successfully, by controller
# TYPE kube_router_controller_sync_failures_total counter
kube_router_controller_sync_failures_total{controller="NetworkPolicyController"} 0
`
		require.NoError(t, testutil.GatherAndCompare(registry, strings.NewReader(expected),
			"kube_router_controller_sync_failures_total"))
		assert.Positive(t, testutil.ToFloat64(
			ControllerSyncLastSuccess.WithLabelValues("NetworkPolicyController")))
	})

	t.Run("a failure does not advance the last success timestamp", func(t *testing.T) {
		gatherSyncMetrics(t)
		lastSuccess := ControllerSyncLastSuccess.WithLabelValues("NetworkServicesController")

		RecordSyncResult(healthcheck.NetworkServicesController, nil)
		stamped := testutil.ToFloat64(lastSuccess)
		require.Positive(t, stamped)

		RecordSyncResult(healthcheck.NetworkServicesController, errors.New("ipvs services: no such device"))

		assert.Equal(t, stamped, testutil.ToFloat64(lastSuccess),
			"a failed sync must leave the previous success timestamp alone")
		assert.Equal(t, float64(1), testutil.ToFloat64(
			ControllerSyncFailures.WithLabelValues("NetworkServicesController")))
	})

	t.Run("only the reported controller gets a series", func(t *testing.T) {
		registry := gatherSyncMetrics(t)

		RecordSyncResult(healthcheck.RouteSyncController, errors.New("route could not be replaced"))

		assert.Equal(t, 1, testutil.CollectAndCount(ControllerSyncFailures))
		count, err := testutil.GatherAndCount(registry, "kube_router_controller_sync_last_success")
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	})

	t.Run("repeated failures accumulate on the counter", func(t *testing.T) {
		gatherSyncMetrics(t)

		for range 3 {
			RecordSyncResult(healthcheck.NetworkRoutesController, errors.New("ipset sync failed"))
		}

		assert.Equal(t, float64(3), testutil.ToFloat64(
			ControllerSyncFailures.WithLabelValues("NetworkRoutesController")))
	})

	t.Run("a later success advances the timestamp", func(t *testing.T) {
		gatherSyncMetrics(t)
		before := float64(time.Now().Unix())

		RecordSyncResult(healthcheck.NetworkRoutesController, errors.New("transient"))
		RecordSyncResult(healthcheck.NetworkRoutesController, nil)

		assert.GreaterOrEqual(t, testutil.ToFloat64(
			ControllerSyncLastSuccess.WithLabelValues("NetworkRoutesController")), before)
	})
}

// TestRunObservedSync checks the wrapper ties the two halves of the contract together: both beats
// go out, the outcome lands in metrics, and the error comes back for the caller to log
func TestRunObservedSync(t *testing.T) {
	tests := []struct {
		name         string
		syncErr      error
		wantFailures float64
	}{
		{name: "successful sync stamps last success", syncErr: nil, wantFailures: 0},
		{name: "failed sync counts a failure", syncErr: errors.New("ipset sync failed"), wantFailures: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gatherSyncMetrics(t)
			channel := make(chan *healthcheck.ControllerHeartbeat, 2)
			before := float64(time.Now().Unix())

			err := RunObservedSync(channel, healthcheck.NetworkPolicyController, func() error { return tt.syncErr })

			assert.Equal(t, tt.syncErr, err, "the sync's error should be returned unchanged")
			assert.Len(t, channel, 2, "a beat should be sent before and after the sync regardless of outcome")
			assert.Equal(t, tt.wantFailures, testutil.ToFloat64(
				ControllerSyncFailures.WithLabelValues("NetworkPolicyController")))
			if tt.syncErr == nil {
				assert.GreaterOrEqual(t, testutil.ToFloat64(
					ControllerSyncLastSuccess.WithLabelValues("NetworkPolicyController")), before)
			}
		})
	}
}

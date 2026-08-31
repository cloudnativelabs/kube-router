package routes

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"

	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/v2/pkg/metrics"
)

var (
	testRoutes = map[string]string{
		"192.168.0.1": "192.168.0.0/24",
		"10.255.0.1":  "10.255.0.0/16",
	}
	_, testAddRouteIPNet, _ = net.ParseCIDR("192.168.1.0/24")
	testAddRouteRoute       = generateTestRoute("192.168.1.0/24", "192.168.1.1")
)

func generateTestRoute(dstCIDR string, dstGateway string) *netlink.Route {
	ip, ipNet, _ := net.ParseCIDR(dstCIDR)
	gwIP := net.ParseIP(dstGateway)
	return &netlink.Route{
		Dst: &net.IPNet{
			IP:   ip,
			Mask: ipNet.Mask,
		},
		Gw: gwIP,
	}
}

func generateTestRouteMap(inputRouteMap map[string]string) map[string]*netlink.Route {
	testRoutes := make(map[string]*netlink.Route)
	for gw, dst := range inputRouteMap {
		testRoutes[dst] = generateTestRoute(dst, gw)
	}
	return testRoutes
}

// mockNetlink guards its fields with a mutex because the route syncer calls mockRouteReplace from
// its own goroutine while tests read currentRoute and swap out wg from the test goroutine
type mockNetlink struct {
	mu           sync.Mutex
	currentRoute *netlink.Route
	pause        time.Duration
	wg           *sync.WaitGroup
	replaceErr   error
}

func (mnl *mockNetlink) mockRouteReplace(route *netlink.Route) error {
	mnl.mu.Lock()
	mnl.currentRoute = route
	wg := mnl.wg
	pause := mnl.pause
	err := mnl.replaceErr
	mnl.mu.Unlock()
	if wg != nil {
		wg.Done()
		time.Sleep(pause)
	}
	return err
}

func (mnl *mockNetlink) getCurrentRoute() *netlink.Route {
	mnl.mu.Lock()
	defer mnl.mu.Unlock()
	return mnl.currentRoute
}

func (mnl *mockNetlink) setWaitGroup(wg *sync.WaitGroup) {
	mnl.mu.Lock()
	defer mnl.mu.Unlock()
	mnl.wg = wg
}

func Test_syncLocalRouteTable(t *testing.T) {
	prepSyncLocalTest := func() (*mockNetlink, *RouteSync) {
		// Create myNetlink so that it will wait 200 milliseconds on routeReplace and artificially hold its lock
		myNetlink := mockNetlink{}
		myNetlink.pause = time.Millisecond * 200

		// Create a route replacer and seed it with some routes to iterate over
		syncer := NewRouteSyncer(15*time.Second, false)
		syncer.routeTableStateMap = generateTestRouteMap(testRoutes)

		// Replace the netlink.RouteReplace function with our own mock function that includes a WaitGroup for syncing
		// and an artificial pause and won't interact with the OS
		syncer.routeReplacer = myNetlink.mockRouteReplace

		return &myNetlink, syncer
	}

	waitForSyncLocalRouteToAcquireLock := func(myNetlink *mockNetlink, syncer *RouteSync) {
		// Launch syncLocalRouteTable in a separate goroutine so that we can try to inject a route into the map while it
		// is syncing. Then wait on the wait group so that we know that syncLocalRouteTable has a hold on the lock when
		// we try to use it in addInjectedRoute() below
		wg := &sync.WaitGroup{}
		wg.Add(1)
		myNetlink.setWaitGroup(wg)
		go func() {
			_ = syncer.SyncLocalRouteTable()
		}()

		// Now we know that the syncLocalRouteTable() is paused on our artificial wait we added above
		wg.Wait()
		// We no longer need the wait group, so we change it to a nil reference so that it won't come into play in the
		// next iteration of the route map
		myNetlink.setWaitGroup(nil)
	}

	t.Run("Ensure addInjectedRoute is goroutine safe", func(t *testing.T) {
		myNetlink, syncer := prepSyncLocalTest()

		waitForSyncLocalRouteToAcquireLock(myNetlink, syncer)

		// By measuring how much time it takes to inject the route we can understand whether addInjectedRoute waited
		// for the lock to be returned or not
		start := time.Now()
		syncer.AddInjectedRoute(testAddRouteIPNet, testAddRouteRoute)
		duration := time.Since(start)

		// We give ourselves a bit of leeway here, and say that if we were forced to wait for at least 190 milliseconds
		// then that is evidence that execution was stalled while trying to acquire a lock from syncLocalRouteTable()
		assert.Greater(t, duration, time.Millisecond*190,
			"Expected addInjectedRoute to take longer than 190 milliseconds to prove locking works")
	})

	t.Run("Ensure delInjectedRoute is goroutine safe", func(t *testing.T) {
		myNetlink, syncer := prepSyncLocalTest()

		waitForSyncLocalRouteToAcquireLock(myNetlink, syncer)

		// By measuring how much time it takes to inject the route we can understand whether addInjectedRoute waited
		// for the lock to be returned or not
		start := time.Now()
		syncer.DelInjectedRoute(testAddRouteIPNet)
		duration := time.Since(start)

		// We give ourselves a bit of leeway here, and say that if we were forced to wait for at least 190 milliseconds
		// then that is evidence that execution was stalled while trying to acquire a lock from syncLocalRouteTable()
		assert.Greater(t, duration, time.Millisecond*190,
			"Expected addInjectedRoute to take longer than 190 milliseconds to prove locking works")
	})
}

func Test_routeSyncer_run(t *testing.T) {
	// Taken from:https://stackoverflow.com/questions/32840687/timeout-for-waitgroup-wait
	// waitTimeout waits for the waitgroup for the specified max timeout.
	// Returns true if waiting timed out.
	waitTimeout := func(wg *sync.WaitGroup, timeout time.Duration) bool {
		c := make(chan struct{})
		go func() {
			defer close(c)
			wg.Wait()
		}()
		select {
		case <-c:
			return false // completed normally
		case <-time.After(timeout):
			return true // timed out
		}
	}

	t.Run("Ensure that run goroutine shuts down correctly on stop", func(t *testing.T) {
		// Setup routeSyncer to run 10 times a second
		syncer := NewRouteSyncer(100*time.Millisecond, false)
		myNetLink := mockNetlink{}
		syncer.routeReplacer = myNetLink.mockRouteReplace
		syncer.routeTableStateMap = generateTestRouteMap(testRoutes)
		stopCh := make(chan struct{})
		wg := sync.WaitGroup{}

		// For a sanity check that the currentRoute on the mock object is nil to start with as we'll rely on this later
		assert.Nil(t, myNetLink.getCurrentRoute(), "currentRoute should be nil when the syncer hasn't run")

		syncer.Run(nil, stopCh, &wg)

		time.Sleep(110 * time.Millisecond)

		assert.NotNil(t, myNetLink.getCurrentRoute(),
			"the syncer should have run by now and populated currentRoute")

		// Simulate a shutdown
		close(stopCh)
		// WaitGroup should close out before our timeout
		timedOut := waitTimeout(&wg, 110*time.Millisecond)

		assert.False(t, timedOut, "WaitGroup should have marked itself as done instead of timing out")
	})
}

// Test_routeSyncerHeartbeat covers the reversal here, since we used to withhold the beat on a
// failed route replace and restart kube-router over a problem a restart could never fix
func Test_routeSyncerHeartbeat(t *testing.T) {
	controllerLabel := healthcheck.HeartBeatCompNames[healthcheck.RouteSyncController]

	tests := []struct {
		name         string
		replaceErr   error
		wantFailures bool
	}{
		{
			name:         "successful sync sends a heartbeat",
			replaceErr:   nil,
			wantFailures: false,
		},
		{
			name:         "failed sync still sends a heartbeat",
			replaceErr:   errors.New("network is unreachable"),
			wantFailures: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syncer := NewRouteSyncer(50*time.Millisecond, false)
			myNetLink := mockNetlink{replaceErr: tt.replaceErr}
			syncer.routeReplacer = myNetLink.mockRouteReplace
			syncer.routeTableStateMap = generateTestRouteMap(testRoutes)

			// Big enough that the loop's dual beats can never block the sync goroutine mid-send,
			// which would keep it from ever seeing stopCh close
			healthChan := make(chan *healthcheck.ControllerHeartbeat, 128)
			stopCh := make(chan struct{})
			wg := sync.WaitGroup{}

			startedAt := float64(time.Now().Unix())
			failuresBefore := testutil.ToFloat64(metrics.ControllerSyncFailures.WithLabelValues(controllerLabel))
			successBefore := testutil.ToFloat64(metrics.ControllerSyncLastSuccess.WithLabelValues(controllerLabel))

			syncer.Run(healthChan, stopCh, &wg)

			// One beat at iteration start and one at iteration end, both regardless of the outcome
			for _, when := range []string{"start", "end"} {
				select {
				case beat := <-healthChan:
					assert.Equal(t, healthcheck.RouteSyncController, beat.Component,
						"the heartbeat should be attributed to the route sync controller")
				case <-time.After(time.Second):
					t.Fatalf("the route syncer must send a heartbeat at iteration %s regardless of "+
						"whether the sync succeeded", when)
				}
			}

			// Shut down first so the assertions don't race the iteration recording its metrics
			close(stopCh)
			wg.Wait()

			failuresAfter := testutil.ToFloat64(metrics.ControllerSyncFailures.WithLabelValues(controllerLabel))
			successAfter := testutil.ToFloat64(metrics.ControllerSyncLastSuccess.WithLabelValues(controllerLabel))

			if tt.wantFailures {
				assert.Greater(t, failuresAfter, failuresBefore,
					"a route that cannot be replaced should move the sync failure counter")
				assert.Equal(t, successBefore, successAfter,
					"a failed sync should leave the last success gauge alone")
			} else {
				assert.Equal(t, failuresBefore, failuresAfter,
					"a clean sync should not move the sync failure counter")
				assert.GreaterOrEqual(t, successAfter, startedAt,
					"a clean sync should stamp the last success gauge with the current time")
			}
		})
	}
}

package routes

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
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

type mockNetlink struct {
	currentRoute *netlink.Route
	pause        time.Duration
	wg           *sync.WaitGroup
}

func (mnl *mockNetlink) mockRouteReplace(route *netlink.Route) error {
	mnl.currentRoute = route
	if mnl.wg != nil {
		mnl.wg.Done()
		time.Sleep(mnl.pause)
	}
	return nil
}

func Test_syncLocalRouteTable(t *testing.T) {
	prepSyncLocalTest := func() (*mockNetlink, *RouteSync) {
		// Create myNetlink so that it will wait 200 milliseconds on routeReplace and artificially hold its lock
		myNetlink := mockNetlink{}
		myNetlink.pause = time.Millisecond * 200

		// Create a route replacer and seed it with some routes to iterate over
		syncer := NewRouteSyncer(15 * time.Second)
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
		myNetlink.wg = &sync.WaitGroup{}
		myNetlink.wg.Add(1)
		go func() {
			_ = syncer.SyncLocalRouteTable()
		}()

		// Now we know that the syncLocalRouteTable() is paused on our artificial wait we added above
		myNetlink.wg.Wait()
		// We no longer need the wait group, so we change it to a nil reference so that it won't come into play in the
		// next iteration of the route map
		myNetlink.wg = nil
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
		syncer := NewRouteSyncer(100 * time.Millisecond)
		myNetLink := mockNetlink{}
		syncer.routeReplacer = myNetLink.mockRouteReplace
		syncer.routeTableStateMap = generateTestRouteMap(testRoutes)
		stopCh := make(chan struct{})
		wg := sync.WaitGroup{}

		// For a sanity check that the currentRoute on the mock object is nil to start with as we'll rely on this later
		assert.Nil(t, myNetLink.currentRoute, "currentRoute should be nil when the syncer hasn't run")

		syncer.Run(nil, stopCh, &wg)

		time.Sleep(110 * time.Millisecond)

		assert.NotNil(t, myNetLink.currentRoute,
			"the syncer should have run by now and populated currentRoute")

		// Simulate a shutdown
		close(stopCh)
		// WaitGroup should close out before our timeout
		timedOut := waitTimeout(&wg, 110*time.Millisecond)

		assert.False(t, timedOut, "WaitGroup should have marked itself as done instead of timing out")
	})
}

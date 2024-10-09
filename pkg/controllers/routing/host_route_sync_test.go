package routing

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg"
	gobgpapi "github.com/osrg/gobgp/v3/api"
	gobgp "github.com/osrg/gobgp/v3/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
	apb "google.golang.org/protobuf/types/known/anypb"
)

var (
	testRoutes = map[string]string{
		"192.168.0.1": "192.168.0.0/24",
		"10.255.0.1":  "10.255.0.0/16",
	}
	_, testAddRouteIPNet, _ = net.ParseCIDR("192.168.1.0/24")
	testAddRouteRoute       = testGenerateRoute("192.168.1.0/24", "192.168.1.1")
)

type testCaseRoute struct {
	dst  string
	mask uint32
	gw   string
	nh   string
}
type testCaseBGPRoute struct {
	dst   *net.IPNet
	route *netlink.Route
	path  *gobgpapi.Path
}

type mockNetlink struct {
	currentRoute     *netlink.Route
	currentDelSubnet *net.IPNet
	pause            time.Duration
	wg               *sync.WaitGroup
}

func (mnl *mockNetlink) mockRouteAction(route *netlink.Route) error {
	mnl.currentRoute = route
	if mnl.wg != nil {
		mnl.wg.Done()
		time.Sleep(mnl.pause)
	}
	return nil
}

func (mnl *mockNetlink) mockDestinationDelete(destinationSubnet *net.IPNet) error {
	mnl.currentDelSubnet = destinationSubnet
	if mnl.wg != nil {
		mnl.wg.Done()
		time.Sleep(mnl.pause)
	}
	return nil
}

func (mnl *mockNetlink) waitForSyncLocalRouteToAcquireLock(syncer pkg.RouteSyncer) {
	// Launch syncLocalRouteTable in a separate goroutine so that we can try to inject a route into the map while it
	// is syncing. Then wait on the wait group so that we know that syncLocalRouteTable has a hold on the lock when
	// we try to use it in addInjectedRoute() below
	mnl.wg = &sync.WaitGroup{}
	mnl.wg.Add(1)
	go syncer.SyncLocalRouteTable()

	// Now we know that the syncLocalRouteTable() is paused on our artificial wait we added above
	mnl.wg.Wait()
	// We no longer need the wait group, so we change it to a nil reference so that it won't come into play in the
	// next iteration of the route map
	mnl.wg = nil
}

func (mnl *mockNetlink) wasCalled() bool {
	return mnl.currentRoute != nil
}

func testCreateRoutes(routes []testCaseRoute) []testCaseBGPRoute {
	convertedRoutes := make([]testCaseBGPRoute, len(routes))
	for idx, route := range routes {
		nlri, _ := apb.New(&gobgpapi.IPAddressPrefix{
			Prefix:    route.dst,
			PrefixLen: route.mask,
		})
		origin, _ := apb.New(&gobgpapi.OriginAttribute{
			Origin: 0,
		})
		nextHop, _ := apb.New(&gobgpapi.NextHopAttribute{
			NextHop: route.nh,
		})
		pattrs := []*apb.Any{origin, nextHop}

		_, dst, _ := net.ParseCIDR(route.dst)

		var family *gobgpapi.Family
		if dst.IP.To4() != nil {
			family = &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP, Safi: gobgpapi.Family_SAFI_UNICAST}
		} else {
			family = &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP6, Safi: gobgpapi.Family_SAFI_UNICAST}
		}

		convertedRoutes[idx] = testCaseBGPRoute{
			dst:   dst,
			route: testGenerateRoute(route.dst, route.gw),
			path: &gobgpapi.Path{
				Family: family,
				Nlri:   nlri,
				Pattrs: pattrs,
			},
		}
	}

	return convertedRoutes
}

func testGenerateRoute(dstCIDR string, dstGateway string) *netlink.Route {
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

func testGenerateRouteMap(inputRouteMap map[string]string) map[string]*netlink.Route {
	testRoutes := make(map[string]*netlink.Route)
	for gw, dst := range inputRouteMap {
		testRoutes[dst] = testGenerateRoute(dst, gw)
	}
	return testRoutes
}

func Test_syncLocalRouteTable(t *testing.T) {
	prepSyncLocalTest := func() (*mockNetlink, *RouteSync) {
		// Create myNetlink so that it will wait 200 milliseconds on routeReplace and artificially hold its lock
		myNetlink := mockNetlink{}
		myNetlink.pause = time.Millisecond * 200

		// Create a route replacer and seed it with some routes to iterate over
		syncer := NewRouteSyncer(15 * time.Second)
		syncer.routeTableStateMap = testGenerateRouteMap(testRoutes)

		// Replace the netlink.RouteReplace function with our own mock function that includes a WaitGroup for syncing
		// and an artificial pause and won't interact with the OS
		syncer.routeReplacer = myNetlink.mockRouteAction

		return &myNetlink, syncer
	}

	t.Run("Ensure addInjectedRoute is goroutine safe", func(t *testing.T) {
		myNetlink, syncer := prepSyncLocalTest()

		myNetlink.waitForSyncLocalRouteToAcquireLock(syncer)

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

		myNetlink.waitForSyncLocalRouteToAcquireLock(syncer)

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
		syncer.routeReplacer = myNetLink.mockRouteAction
		syncer.routeTableStateMap = testGenerateRouteMap(testRoutes)
		stopCh := make(chan struct{})
		wg := sync.WaitGroup{}

		// For a sanity check that the currentRoute on the mock object is nil to start with as we'll rely on this later
		assert.Nil(t, myNetLink.currentRoute, "currentRoute should be nil when the syncer hasn't run")

		syncer.Run(stopCh, &wg)

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

func Test_routeSyncer_checkAgainstBGPCache(t *testing.T) {

	testRoutes := []testCaseRoute{
		{
			dst:  "10.0.0.2/32",
			mask: 32,
			gw:   "10.0.0.1",
			nh:   "192.168.1.1",
		},
		{
			dst:  "2001:db8:1::2/128",
			mask: 128,
			gw:   "2001:db8:1::1",
			nh:   "2001:db8:2::1",
		},
	}
	createTestRouteMap := func(routes []testCaseRoute) map[string]string {
		testRouteMap := make(map[string]string, 0)
		for _, rt := range routes {
			testRouteMap[rt.gw] = rt.dst
		}
		return testRouteMap
	}

	testSetup := func() (*mockNetlink, *RouteSync) {
		// Setup routeSyncer to run 10 times a second
		syncer := NewRouteSyncer(100 * time.Millisecond)
		syncer.routeTableStateMap = testGenerateRouteMap(createTestRouteMap(testRoutes))
		myNetLink := mockNetlink{}
		syncer.routeReplacer = myNetLink.mockRouteAction
		syncer.routeAdder = myNetLink.mockRouteAction
		syncer.routeDeleter = myNetLink.mockDestinationDelete

		return &myNetLink, syncer
	}

	testStartBGPServer := func() (*gobgp.BgpServer, error) {
		bgpServer := gobgp.NewBgpServer()
		go bgpServer.Serve()

		err := bgpServer.StartBgp(context.Background(), &gobgpapi.StartBgpRequest{
			Global: &gobgpapi.Global{
				Asn:        65000,
				RouterId:   "192.168.0.1",
				ListenPort: 10000,
			},
		})
		return bgpServer, err
	}

	t.Run("Ensure proper error when BGP Server is Unset", func(t *testing.T) {
		// Setup routeSyncer to run 10 times a second
		syncer := NewRouteSyncer(100 * time.Millisecond)
		err := syncer.checkCacheAgainstBGP()
		assert.NotNil(t, err, "Expected an error when BGP server is unset")
		assert.IsType(t, BGPServerUnsetError{}, err, "Expected an BGPServerUnsetError error")
	})

	t.Run("Ensure no action is taken when routes are in sync", func(t *testing.T) {
		myNetLink, syncer := testSetup()

		// Start the BGP server
		bgpServer, err := testStartBGPServer()
		if err != nil {
			t.Fatalf("Failed to start BGP server: %v", err)
		}
		defer func() { _ = bgpServer.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{}) }()

		syncer.bgpServer = bgpServer

		bgpRoutes := testCreateRoutes(testRoutes)

		for _, route := range bgpRoutes {
			_, err := bgpServer.AddPath(context.Background(), &gobgpapi.AddPathRequest{
				Path: route.path,
			})
			if err != nil {
				t.Fatalf("Failed to advertise route: %v", err)
			}
		}

		err = syncer.checkCacheAgainstBGP()
		assert.NoError(t, err, "Expected no error when BGP and local routes are in sync")

		assert.False(t, myNetLink.wasCalled(), "Expected no calls to netlink when BGP and local routes are in sync")
	})
}

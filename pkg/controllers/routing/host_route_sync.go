package routing

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg"
	"github.com/cloudnativelabs/kube-router/v2/pkg/bgp"
	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/v2/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/v2/pkg/routes"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

type BGPPathListerUnsetError struct{}
type BGPListError struct {
	msg string
	err error
}

func (b BGPPathListerUnsetError) Error() string {
	return "BGP server not yet specified"
}

func newBGPListError(msg string, err error) BGPListError {
	return BGPListError{msg: msg, err: err}
}

func (b BGPListError) Error() string {
	if b.msg != "" {
		if b.err != nil {
			return fmt.Sprintf("%s: %v", b.msg, b.err)
		}
		return b.msg
	}
	return "Unable to list BGP"
}

func (b BGPListError) Unwrap() error {
	return b.err
}

// RouteSync is a struct that holds all of the information needed for syncing routes to the kernel's routing table
type RouteSync struct {
	routeTableStateMap map[string]*netlink.Route
	routeSyncPeriod    time.Duration
	mutex              sync.Mutex
	nia                pkg.NodeIPAware
	routeReplacer      func(route *netlink.Route) error
	routeDeleter       func(destinationSubnet *net.IPNet) error
	routeAdder         func(route *netlink.Route) error
	routeInjector      pkg.RouteInjector
	pathLister         pkg.BGPPathLister
}

// addInjectedRoute adds a route to the route map that is regularly synced to the kernel's routing table
func (rs *RouteSync) AddInjectedRoute(dst *net.IPNet, route *netlink.Route) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	klog.V(3).Infof("Adding route for destination: %s", dst)
	rs.routeTableStateMap[dst.String()] = route
	metrics.HostRoutesSyncedGauge.Set(float64(len(rs.routeTableStateMap)))
}

// delInjectedRoute delete a route from the route map that is regularly synced to the kernel's routing table
func (rs *RouteSync) DelInjectedRoute(dst *net.IPNet) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	if _, ok := rs.routeTableStateMap[dst.String()]; ok {
		klog.V(3).Infof("Removing route for destination: %s", dst)
		delete(rs.routeTableStateMap, dst.String())
		err := routes.DeleteByDestination(dst)
		if err != nil {
			klog.Errorf("Failed to cleanup routes: %v", err)
		}
		metrics.HostRoutesSyncedGauge.Set(float64(len(rs.routeTableStateMap)))
	}
}

func (rs *RouteSync) checkState(authoritativeState map[string]*netlink.Route) ([]*netlink.Route,
	[]*netlink.Route, []*netlink.Route) {
	// While we're iterating over the state map, we should hold the mutex to prevent any other operations from
	// interfering with the state map
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	routesToAdd := make([]*netlink.Route, 0)
	routesToChange := make([]*netlink.Route, 0)
	routesToDelete := make([]*netlink.Route, 0)

	routeEquals := func(route1, route2 *netlink.Route) bool {
		if !route1.Dst.IP.Equal(route2.Dst.IP) {
			return false
		}
		if !bytes.Equal(route1.Dst.Mask, route2.Dst.Mask) {
			return false
		}
		if !route1.Gw.Equal(route2.Gw) {
			return false
		}
		return true
	}

	// Compare the routes source of truth from BGP to the routes in our state, searching for any routes that might be
	// missing from the state and adding them if they are missing
	for dst, route := range authoritativeState {
		if cachedRoute, ok := rs.routeTableStateMap[dst]; ok {
			// Check to see if the cached route is the same as the authoritative route
			if routeEquals(route, cachedRoute) {
				klog.V(2).Infof("Route already exists for destination: %s - (%s)", dst, route)
				continue
			}

			routesToChange = append(routesToChange, route)
			continue
		}

		routesToAdd = append(routesToAdd, route)
	}

	// Compare the routes in our state to the routes source of truth from BGP, searching for any routes that might be
	// missing from BGP and deleting them if they are missing
	for dst, route := range rs.routeTableStateMap {
		if _, ok := authoritativeState[dst]; ok {
			klog.V(2).Infof("Route already exists for destination: %s - (%s)", dst, route)
			continue
		}

		routesToDelete = append(routesToDelete, route)
	}

	return routesToAdd, routesToChange, routesToDelete
}

func (rs *RouteSync) convertPathsToRouteMap(path []*gobgpapi.Path) map[string]*netlink.Route {
	routeMap := make(map[string]*netlink.Route, 0)
	for _, p := range path {
		klog.V(3).Infof("Path: %v", p)

		// Leave out withdraw paths from the map, we don't need to worry about tracking them because we are going to
		// delete any routes not found in the map we're returning anyway
		if p.IsWithdraw {
			klog.V(3).Infof("Path is a withdrawal, skipping: %s", p)
			continue
		}

		// Leave out paths that are not the best path, as we only consider the best paths in kube-router
		if !p.Best {
			klog.V(3).Infof("Path is not the best path, skipping: %s", p)
			continue
		}

		// Seems like a valid path, let's parse it
		dst, nh, err := bgp.ParsePath(p)
		if err != nil {
			klog.Warningf("Failed to parse BGP path, not failing so as to not block updating paths that are "+
				"valid: %v", err)
		}

		// When we list paths in this way we'll also get our own paths (e.g. when we are our own next hop), leave these
		// ones out so that we don't create unneeded routes
		if nh.Equal(rs.nia.GetPrimaryNodeIP()) {
			klog.V(3).Infof("Path is to our own node, skipping: %s", p)
			continue
		}

		// Add path to our map
		routeMap[dst.String()] = &netlink.Route{
			Dst:      dst,
			Gw:       nh,
			Protocol: routes.ZebraOriginator,
		}
	}

	return routeMap
}

func (rs *RouteSync) checkCacheAgainstBGP() error {
	klog.V(2).Info("Initiating route cache update")

	// During startup, it is possible for this function to possibly be called before the BGP server has been set on it,
	// in this case, return BGPServerUnsetError
	if rs.pathLister == nil {
		return BGPPathListerUnsetError{}
	}

	// Create a var for tracking all of the paths we're about to get
	allPaths := make([]*gobgpapi.Path, 0)
	pathList := func(path *gobgpapi.Destination) {
		allPaths = append(allPaths, path.Paths...)
	}

	// Call ListPath() for all families passing in our pathList function from above, to set allPaths
	for _, family := range []*gobgpapi.Family{
		{Afi: gobgpapi.Family_AFI_IP, Safi: gobgpapi.Family_SAFI_UNICAST},
		{Afi: gobgpapi.Family_AFI_IP6, Safi: gobgpapi.Family_SAFI_UNICAST}} {
		err := rs.pathLister.ListPath(context.Background(), &gobgpapi.ListPathRequest{Family: family}, pathList)
		if err != nil {
			return newBGPListError("Failed to list BGP paths", err)
		}
	}

	// Convert all paths to a map of routes, this serves as our authoritative source of truth for what routes should be
	bgpRoutes := rs.convertPathsToRouteMap(allPaths)

	// Check the state of the routes against the authoritative source of truth
	routesToAdd, routesToChange, routesToDelete := rs.checkState(bgpRoutes)

	// Add missing routes
	for _, route := range routesToAdd {
		routeAdded, err := rs.routeInjector.InjectRoute(route.Dst, route.Gw)
		if err != nil {
			klog.Errorf("Failed to inject route: %v", err)
		}
		if routeAdded {
			klog.Infof("Found route from BGP that did not exist in state, adding to state: %s", route)
			metrics.HostRoutesStaleAddedCounter.Inc()
		}
	}

	for _, route := range routesToChange {
		klog.Infof("Found route from BGP that was different than state, updating: %s", route)
		err := rs.routeDeleter(route.Dst)
		if err != nil {
			klog.Errorf("Failed to delete route: %v", err)
		}
		_, err = rs.routeInjector.InjectRoute(route.Dst, route.Gw)
		if err != nil {
			klog.Errorf("Failed to inject route: %v", err)
		}
		metrics.HostRoutesStaleUpdatedCounter.Inc()
	}

	// Delete routes that are no longer in the authoritative source of truth
	for _, route := range routesToDelete {
		klog.Infof("Found route in state that did not exist in BGP, deleting from state: %s", route)
		err := rs.routeDeleter(route.Dst)
		if err != nil {
			klog.Errorf("Failed to delete route: %v", err)
		}
		metrics.HostRoutesStaleRemovedCounter.Inc()
	}

	klog.V(2).Info("Finished route cache update")
	return nil
}

// syncLocalRouteTable iterates over the local route state map and syncs all routes to the kernel's routing table
func (rs *RouteSync) SyncLocalRouteTable() error {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	klog.V(2).Infof("Running local route table synchronization")
	for key, route := range rs.routeTableStateMap {
		klog.V(3).Infof("Syncing route(key: %s): %s -> %s via %s", key, route.Src, route.Dst, route.Gw)
		err := rs.routeReplacer(route)
		if err != nil {
			return err
		}
	}
	return nil
}

// run starts a goroutine that calls syncLocalRouteTable on interval injectedRoutesSyncPeriod
func (rs *RouteSync) Run(healthChan chan<- *pkg.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) {
	// Start route synchronization routine
	wg.Add(1)
	go func(stopCh <-chan struct{}, wg *sync.WaitGroup) {
		defer wg.Done()
		t1 := time.NewTicker(rs.routeSyncPeriod)
		// Check our local state against BGP once for every 5 route syncs
		t2 := time.NewTicker(5 * rs.routeSyncPeriod)
		defer t1.Stop()
		for {
			select {
			case <-t1.C:
				err := rs.SyncLocalRouteTable()
				if err != nil {
					klog.Errorf("Route could not be replaced due to : " + err.Error())
				}
				// Some of our unit tests send a nil health channel
				if nil != healthChan {
					healthcheck.SendHeartBeat(healthChan, pkg.HeartBeatCompHostRouteSync)
				}
			case <-t2.C:
				err := rs.checkCacheAgainstBGP()
				if err != nil {
					switch err.(type) {
					case BGPPathListerUnsetError:
						klog.Warningf("BGP server not yet set, cannot check cache against BGP")
					case BGPListError:
						klog.Errorf("Failed to check cache against BGP due to BGP error: %v", err)
					default:
						klog.Errorf("Failed to check cache against BGP: %v", err)
					}
				}
			case <-stopCh:
				klog.Infof("Shutting down local route synchronization")
				return
			}
		}
	}(stopCh, wg)
}

// addBGPPathLister adds a BGP server to the routeSyncer so that it can be used to advertise routes
func (rs *RouteSync) AddBGPPathLister(pl pkg.BGPPathLister) {
	rs.pathLister = pl
}

// NewRouteSyncer creates a new routeSyncer that, when run, will sync routes kept in its local state table every
// syncPeriod
func NewRouteSyncer(ri pkg.RouteInjector, nia pkg.NodeIPAware, syncPeriod time.Duration,
	registerMetrics bool) *RouteSync {
	rs := RouteSync{}
	rs.routeTableStateMap = make(map[string]*netlink.Route)
	rs.nia = nia
	rs.routeSyncPeriod = syncPeriod
	rs.mutex = sync.Mutex{}

	// We substitute the RouteR* functions here so that we can easily monkey patch it in our unit tests
	rs.routeReplacer = netlink.RouteReplace
	rs.routeDeleter = routes.DeleteByDestination
	rs.routeAdder = netlink.RouteAdd
	rs.routeInjector = ri

	// Register metrics
	if registerMetrics {
		prometheus.MustRegister(metrics.HostRoutesSyncedGauge, metrics.HostRoutesStaleAddedCounter,
			metrics.HostRoutesStaleRemovedCounter, metrics.HostRoutesStaleUpdatedCounter)
	}

	return &rs
}

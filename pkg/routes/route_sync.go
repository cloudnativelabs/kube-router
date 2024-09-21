package routes

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	gobgp "github.com/osrg/gobgp/v3/pkg/server"
	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

type BGPServerUnsetError struct{}
type BGPListError struct {
	msg string
	err error
}

func (b BGPServerUnsetError) Error() string {
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

// RouteSyncer is an interface that defines the methods needed to sync routes to the kernel's routing table
type RouteSyncer interface {
	AddInjectedRoute(dst *net.IPNet, route *netlink.Route)
	DelInjectedRoute(dst *net.IPNet)
	Run(stopCh <-chan struct{}, wg *sync.WaitGroup)
	SyncLocalRouteTable()
}

// RouteSync is a struct that holds all of the information needed for syncing routes to the kernel's routing table
type RouteSync struct {
	routeTableStateMap       map[string]*netlink.Route
	injectedRoutesSyncPeriod time.Duration
	mutex                    sync.Mutex
	routeReplacer            func(route *netlink.Route) error
	routeDeleter             func(destinationSubnet *net.IPNet) error
	routeAdder               func(route *netlink.Route) error
	bgpServer                *gobgp.BgpServer
}

// addInjectedRoute adds a route to the route map that is regularly synced to the kernel's routing table
func (rs *RouteSync) AddInjectedRoute(dst *net.IPNet, route *netlink.Route) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	klog.V(3).Infof("Adding route for destination: %s", dst)
	rs.routeTableStateMap[dst.String()] = route
}

// delInjectedRoute delete a route from the route map that is regularly synced to the kernel's routing table
func (rs *RouteSync) DelInjectedRoute(dst *net.IPNet) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	if _, ok := rs.routeTableStateMap[dst.String()]; ok {
		klog.V(3).Infof("Removing route for destination: %s", dst)
		delete(rs.routeTableStateMap, dst.String())
		err := DeleteByDestination(dst)
		if err != nil {
			klog.Errorf("Failed to cleanup routes: %v", err)
		}
	}
}

func (rs *RouteSync) checkCacheAgainstBGP() error {
	convertPathsToRouteMap := func(path []*gobgpapi.Path) map[string]*netlink.Route {
		routeMap := make(map[string]*netlink.Route, 0)
		for _, p := range path {
			klog.V(3).Infof("Path: %v", p)
			/*
			dst, nh, err := routing.ParseBGPPath(p)
			if err != nil {
				klog.Warningf("Failed to parse BGP path, not failing so as to not block updating paths that are "+
					"valid: %v", err)
			}
			routeMap[dst.String()] = &netlink.Route{
				Dst: dst,
				Gw:  nh,
				Protocol: ZebraOriginator,
			}*/
		}
		return routeMap
	}

	if rs.bgpServer == nil {
		return BGPServerUnsetError{}
	}
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	allPaths := make([]*gobgpapi.Path, 0)

	pathList := func(path *gobgpapi.Destination) {
		allPaths = append(allPaths, path.Paths...)
	}

	for _, family := range []*gobgpapi.Family{
		{Afi: gobgpapi.Family_AFI_IP, Safi: gobgpapi.Family_SAFI_UNICAST},
		{Afi: gobgpapi.Family_AFI_IP6, Safi: gobgpapi.Family_SAFI_UNICAST}} {
		err := rs.bgpServer.ListPath(context.Background(), &gobgpapi.ListPathRequest{Family: family}, pathList)
		if err != nil {
			return newBGPListError("Failed to list BGP paths", err)
		}
	}

	bgpRoutes := convertPathsToRouteMap(allPaths)

	// REPLACE ME
	for dst, route := range bgpRoutes {
		if dst != "" && route != nil {
			return nil
		}
	}


	return nil
}

// syncLocalRouteTable iterates over the local route state map and syncs all routes to the kernel's routing table
func (rs *RouteSync) SyncLocalRouteTable() {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	klog.V(2).Infof("Running local route table synchronization")
	for _, route := range rs.routeTableStateMap {
		klog.V(3).Infof("Syncing route: %s -> %s via %s", route.Src, route.Dst, route.Gw)
		err := rs.routeReplacer(route)
		if err != nil {
			klog.Errorf("Route could not be replaced due to : " + err.Error())
		}
	}
}

// run starts a goroutine that calls syncLocalRouteTable on interval injectedRoutesSyncPeriod
func (rs *RouteSync) Run(stopCh <-chan struct{}, wg *sync.WaitGroup) {
	// Start route synchronization routine
	wg.Add(1)
	go func(stopCh <-chan struct{}, wg *sync.WaitGroup) {
		defer wg.Done()
		t := time.NewTicker(rs.injectedRoutesSyncPeriod)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				rs.SyncLocalRouteTable()
			case <-stopCh:
				klog.Infof("Shutting down local route synchronization")
				return
			}
		}
	}(stopCh, wg)
}

// addBGPServer adds a BGP server to the routeSyncer so that it can be used to advertise routes
//
//nolint:unused // we're going to implement this later
func (rs *RouteSync) addBGPServer(server *gobgp.BgpServer) {
	rs.bgpServer = server
}

// NewRouteSyncer creates a new routeSyncer that, when run, will sync routes kept in its local state table every
// syncPeriod
func NewRouteSyncer(syncPeriod time.Duration) *RouteSync {
	rs := RouteSync{}
	rs.routeTableStateMap = make(map[string]*netlink.Route)
	rs.injectedRoutesSyncPeriod = syncPeriod
	rs.mutex = sync.Mutex{}

	// We substitute the RouteR* functions here so that we can easily monkey patch it in our unit tests
	rs.routeReplacer = netlink.RouteReplace
	rs.routeDeleter = DeleteByDestination
	rs.routeAdder = netlink.RouteAdd

	return &rs
}

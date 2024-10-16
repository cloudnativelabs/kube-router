package routes

import (
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

// RouteSync is a struct that holds all of the information needed for syncing routes to the kernel's routing table
type RouteSync struct {
	routeTableStateMap       map[string]*netlink.Route
	injectedRoutesSyncPeriod time.Duration
	mutex                    sync.Mutex
	routeReplacer            func(route *netlink.Route) error
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
	}
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

// NewRouteSyncer creates a new routeSyncer that, when run, will sync routes kept in its local state table every
// syncPeriod
func NewRouteSyncer(syncPeriod time.Duration) *RouteSync {
	rs := RouteSync{}
	rs.routeTableStateMap = make(map[string]*netlink.Route)
	rs.injectedRoutesSyncPeriod = syncPeriod
	rs.mutex = sync.Mutex{}
	// We substitute the RouteReplace function here so that we can easily monkey patch it in our unit tests
	rs.routeReplacer = netlink.RouteReplace
	return &rs
}

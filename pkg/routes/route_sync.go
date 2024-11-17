package routes

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/v2/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

type RouteSyncErr struct {
	route *netlink.Route
	err   error
}

func (rse RouteSyncErr) Error() string {
	return fmt.Sprintf("route (%s) encountered the following error while being acted upon: %v", rse.route, rse.err)
}

// RouteSync is a struct that holds all of the information needed for syncing routes to the kernel's routing table
type RouteSync struct {
	routeTableStateMap       map[string]*netlink.Route
	injectedRoutesSyncPeriod time.Duration
	mutex                    sync.Mutex
	routeReplacer            func(route *netlink.Route) error
	metricsEnabled           bool
}

// addInjectedRoute adds a route to the route map that is regularly synced to the kernel's routing table
func (rs *RouteSync) AddInjectedRoute(dst *net.IPNet, route *netlink.Route) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	klog.V(3).Infof("Adding route for destination: %s", dst)
	rs.routeTableStateMap[dst.String()] = route
	if rs.metricsEnabled {
		metrics.ControllerHostRoutesAdded.Inc()
		metrics.ControllerHostRoutesSynced.Set(float64(len(rs.routeTableStateMap)))
	}
}

// delInjectedRoute delete a route from the route map that is regularly synced to the kernel's routing table
func (rs *RouteSync) DelInjectedRoute(dst *net.IPNet) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	if _, ok := rs.routeTableStateMap[dst.String()]; ok {
		klog.V(3).Infof("Removing route for destination: %s", dst)
		delete(rs.routeTableStateMap, dst.String())
	}
	if rs.metricsEnabled {
		metrics.ControllerHostRoutesRemoved.Inc()
		metrics.ControllerHostRoutesSynced.Set(float64(len(rs.routeTableStateMap)))
	}
}

// syncLocalRouteTable iterates over the local route state map and syncs all routes to the kernel's routing table
func (rs *RouteSync) SyncLocalRouteTable() error {
	if rs.metricsEnabled {
		startSyncTime := time.Now()
		defer func(startTime time.Time) {
			runTime := time.Since(startTime)
			metrics.ControllerHostRoutesSyncTime.Observe(runTime.Seconds())
		}(startSyncTime)
	}
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	klog.V(2).Infof("Running local route table synchronization")
	for _, route := range rs.routeTableStateMap {
		klog.V(3).Infof("Syncing route: %s -> %s via %s", route.Src, route.Dst, route.Gw)
		err := rs.routeReplacer(route)
		if err != nil {
			return RouteSyncErr{
				route: route,
				err:   err,
			}
		}
	}
	if rs.metricsEnabled {
		metrics.ControllerHostRoutesSynced.Set(float64(len(rs.routeTableStateMap)))
	}
	return nil
}

// run starts a goroutine that calls syncLocalRouteTable on interval injectedRoutesSyncPeriod
func (rs *RouteSync) Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{},
	wg *sync.WaitGroup) {
	// Start route synchronization routine
	wg.Add(1)
	go func(stopCh <-chan struct{}, wg *sync.WaitGroup) {
		defer wg.Done()
		t := time.NewTicker(rs.injectedRoutesSyncPeriod)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				err := rs.SyncLocalRouteTable()
				if err != nil {
					klog.Errorf("route could not be replaced due to: %v", err)
				}
				// Some of our unit tests send a nil health channel
				if nil != healthChan && err == nil {
					healthcheck.SendHeartBeat(healthChan, healthcheck.RouteSyncController)
				}
			case <-stopCh:
				klog.Infof("Shutting down local route synchronization")
				return
			}
		}
	}(stopCh, wg)
}

// NewRouteSyncer creates a new routeSyncer that, when run, will sync routes kept in its local state table every
// syncPeriod
func NewRouteSyncer(syncPeriod time.Duration, registerMetrics bool) *RouteSync {
	rs := RouteSync{}
	rs.routeTableStateMap = make(map[string]*netlink.Route)
	rs.injectedRoutesSyncPeriod = syncPeriod
	rs.mutex = sync.Mutex{}
	// We substitute the RouteReplace function here so that we can easily monkey patch it in our unit tests
	rs.routeReplacer = netlink.RouteReplace
	rs.metricsEnabled = registerMetrics

	// Register Metrics
	if registerMetrics {
		prometheus.MustRegister(metrics.ControllerHostRoutesSynced, metrics.ControllerHostRoutesSyncTime,
			metrics.ControllerHostRoutesAdded, metrics.ControllerHostRoutesRemoved)
	}

	return &rs
}

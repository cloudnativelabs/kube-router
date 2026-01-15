package metrics

import (
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"context"

	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/version"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/klog/v2"
)

const (
	metricsControllerTickTime = 3 * time.Second
	namespace                 = "kube_router"
)

func newDesc(name, help string, variableLabels []string) *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", name),
		help, variableLabels, nil,
	)
}

var (
	// DefaultRegisterer and DefaultGatherer are the implementations of the
	// prometheus Registerer and Gatherer interfaces that all metrics operations
	// will use. They are variables so that packages that embed this library can
	// replace them at runtime, instead of having to pass around specific
	// registries.
	DefaultRegisterer = prometheus.DefaultRegisterer
	DefaultGatherer   = prometheus.DefaultGatherer
)

var (
	// BuildInfo Expose version and other build information
	BuildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "build_info",
		Help:      "Expose version and other build information",
	}, []string{"goversion", "version"})

	// serviceLabels holds labels for service metrics
	serviceLabels = []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"}

	// ServiceTotalConn Total incoming connections made
	ServiceTotalConn = newDesc(
		"service_total_connections",
		"Total incoming connections made",
		serviceLabels,
	)
	// ServicePacketsIn Total incoming packets
	ServicePacketsIn = newDesc(
		"service_packets_in",
		"Total incoming packets",
		serviceLabels,
	)
	// ServicePacketsOut Total outgoing packets
	ServicePacketsOut = newDesc(
		"service_packets_out",
		"Total outgoing packets",
		serviceLabels,
	)
	// ServiceBytesIn Total incoming bytes
	ServiceBytesIn = newDesc(
		"service_bytes_in",
		"Total incoming bytes",
		serviceLabels,
	)
	// ServiceBytesOut Total outgoing bytes
	ServiceBytesOut = newDesc(
		"service_bytes_out",
		"Total outgoing bytes",
		serviceLabels,
	)
	// ServicePpsIn Incoming packets per second
	ServicePpsIn = newDesc(
		"service_pps_in",
		"Incoming packets per second",
		serviceLabels,
	)
	// ServicePpsOut Outgoing packets per second
	ServicePpsOut = newDesc(
		"service_pps_out",
		"Outgoing packets per second",
		serviceLabels,
	)
	// ServiceCPS Service connections per second
	ServiceCPS = newDesc(
		"service_cps",
		"Service connections per second",
		serviceLabels,
	)
	// ServiceBpsIn Incoming bytes per second
	ServiceBpsIn = newDesc(
		"service_bps_in",
		"Incoming bytes per second",
		serviceLabels,
	)
	// ServiceBpsOut Outgoing bytes per second
	ServiceBpsOut = newDesc(
		"service_bps_out",
		"Outgoing bytes per second",
		serviceLabels,
	)
	// ControllerIpvsServices Number of ipvs services in the instance
	ControllerIpvsServices = newDesc(
		"controller_ipvs_services",
		"Number of ipvs services in the instance",
		nil,
	)
	// ControllerIptablesSyncTime Time it took for controller to sync iptables
	ControllerIptablesSyncTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_iptables_sync_time",
		Help:      "Time it took for controller to sync iptables",
	})
	// ControllerIptablesV4SaveTime Time it took controller to save IPv4 rules
	ControllerIptablesV4SaveTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_iptables_v4_save_time",
		Help:      "Time it took controller to save IPv4 rules",
	})
	// ControllerIptablesV6SaveTime Time to took for controller to save IPv6 rules
	ControllerIptablesV6SaveTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_iptables_v6_save_time",
		Help:      "Time to took for controller to save IPv6 rules",
	})
	// ControllerIptablesV4RestoreTime Time it took for controller to restore IPv4 rules
	ControllerIptablesV4RestoreTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_iptables_v4_restore_time",
		Help:      "Time it took for controller to restore IPv4 rules",
	})
	// ControllerIptablesV6RestoreTime Time it took for controller to restore IPv6 rules
	ControllerIptablesV6RestoreTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_iptables_v6_restore_time",
		Help:      "Time it took for controller to restore IPv6 rules",
	})
	// ControllerIpvsServicesSyncTime Time it took for controller to sync ipvs services
	ControllerIpvsServicesSyncTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_ipvs_services_sync_time",
		Help:      "Time it took for controller to sync ipvs services",
	})
	// ControllerRoutesSyncTime Time it took for controller to sync ipvs services
	ControllerRoutesSyncTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_routes_sync_time",
		Help:      "Time it took for controller to sync routes",
	})
	// ControllerBPGpeers BGP peers in the runtime configuration
	ControllerBPGpeers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_bgp_peers",
		Help:      "BGP peers in the runtime configuration",
	})
	// ControllerBGPInternalPeersSyncTime Time it took to sync internal bgp peers
	ControllerBGPInternalPeersSyncTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_bgp_internal_peers_sync_time",
		Help:      "Time it took to sync internal bgp peers",
	})
	// ControllerBGPadvertisementsReceived Time it took to sync internal bgp peers
	ControllerBGPadvertisementsReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "controller_bgp_advertisements_received",
		Help:      "BGP advertisements received",
	})
	// ControllerBGPadvertisementsSent Time it took to sync internal bgp peers
	ControllerBGPadvertisementsSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "controller_bgp_advertisements_sent",
			Help:      "BGP advertisements sent",
		},
		[]string{"type"},
	)
	// ControllerIpvsMetricsExportTime Time it took to export metrics
	ControllerIpvsMetricsExportTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_ipvs_metrics_export_time",
		Help:      "Time it took to export metrics",
	})
	// ControllerPolicyChainsSyncTime Time it took for controller to sync policys
	ControllerPolicyChainsSyncTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_policy_chains_sync_time",
		Help:      "Time it took for controller to sync policy chains",
	})
	// ControllerPolicyIpsetV4RestoreTime Time it took for controller to restore IPv4 ipsets
	ControllerPolicyIpsetV4RestoreTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_policy_ipset_v4_restore_time",
		Help:      "Time it took for controller to restore IPv4 ipsets",
	})
	// ControllerPolicyIpsetV6RestoreTime Time it took for controller to restore IPv6 ipsets
	ControllerPolicyIpsetV6RestoreTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_policy_ipset_v6_restore_time",
		Help:      "Time it took for controller to restore IPv6 ipsets",
	})
	// ControllerPolicyChains Active policy chains
	ControllerPolicyChains = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_policy_chains",
		Help:      "Active policy chains",
	})
	// ControllerPolicyIpsets Active policy ipsets
	ControllerPolicyIpsets = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_policy_ipsets",
		Help:      "Active policy ipsets",
	})
	// ControllerHostRoutesSyncTime Time it took for the host routes controller to sync to the system
	ControllerHostRoutesSyncTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "host_routes_sync_time",
		Help:      "Time it took for the host routes controller to sync to the system",
	})
	// ControllerHostRoutesSynced Number of host routes currently synced to the system
	ControllerHostRoutesSynced = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "host_routes_synced",
		Help:      "Count of host routes currently synced to the system",
	})
	// ControllerHostRoutesSynced Number of host routes added to the system
	ControllerHostRoutesAdded = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "host_routes_added",
		Help:      "Total count of host routes added to the system",
	})
	// ControllerHostRoutesSynced Number of host routes removed to the system
	ControllerHostRoutesRemoved = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "host_routes_removed",
		Help:      "Total count of host routes removed to the system",
	})
)

// Controller Holds settings for the metrics controller
type Controller struct {
	MetricsPath string
	MetricsAddr string
	MetricsPort uint16
}

// Handler returns a http.Handler for the default registerer and gatherer
func Handler() http.Handler {
	return promhttp.InstrumentMetricHandler(DefaultRegisterer, promhttp.HandlerFor(DefaultGatherer,
		promhttp.HandlerOpts{}))
}

// Run prometheus metrics controller
func (mc *Controller) Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{},
	wg *sync.WaitGroup) {
	t := time.NewTicker(metricsControllerTickTime)
	defer wg.Done()
	klog.Info("Starting metrics controller")

	// register metrics for this controller
	BuildInfo.WithLabelValues(runtime.Version(), version.Version).Set(1)
	DefaultRegisterer.MustRegister(BuildInfo)
	DefaultRegisterer.MustRegister(ControllerIpvsMetricsExportTime)

	mux := http.NewServeMux()

	srv := &http.Server{
		Addr:              mc.MetricsAddr + ":" + strconv.Itoa(int(mc.MetricsPort)),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second}

	// add prometheus handler on metrics path
	mux.Handle(mc.MetricsPath, Handler())

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			// cannot panic, because this probably is an intentional close
			klog.Errorf("Metrics controller error: %s", err)
		}
	}()
	for {
		healthcheck.SendHeartBeat(healthChan, healthcheck.MetricsController)
		select {
		case <-stopCh:
			klog.Infof("Shutting down metrics controller")
			if err := srv.Shutdown(context.Background()); err != nil {
				klog.Errorf("could not shutdown: %v", err)
			}
			return
		case <-t.C:
			klog.V(4).Info("Metrics controller tick")
		}
	}
}

// NewMetricsController returns new MetricController object
func NewMetricsController(config *options.KubeRouterConfig) (*Controller, error) {
	mc := Controller{}
	mc.MetricsAddr = config.MetricsAddr
	mc.MetricsPath = config.MetricsPath
	mc.MetricsPort = config.MetricsPort
	return &mc, nil
}

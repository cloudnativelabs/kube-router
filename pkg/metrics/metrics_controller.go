package metrics

import (
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/version"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/context"
	"k8s.io/klog/v2"
)

const (
	metricsControllerTickTime = 3 * time.Second
	namespace                 = "kube_router"
)

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
	// ServiceTotalConn Total incoming connections made
	ServiceTotalConn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_total_connections",
		Help:      "Total incoming connections made",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServicePacketsIn Total incoming packets
	ServicePacketsIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_packets_in",
		Help:      "Total incoming packets",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServicePacketsOut Total outgoing packets
	ServicePacketsOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_packets_out",
		Help:      "Total outgoing packets",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServiceBytesIn Total incoming bytes
	ServiceBytesIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_bytes_in",
		Help:      "Total incoming bytes",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServiceBytesOut Total outgoing bytes
	ServiceBytesOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_bytes_out",
		Help:      "Total outgoing bytes",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServicePpsIn Incoming packets per second
	ServicePpsIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_pps_in",
		Help:      "Incoming packets per second",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServicePpsOut Outgoing packets per second
	ServicePpsOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_pps_out",
		Help:      "Outgoing packets per second",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServiceCPS Service connections per second
	ServiceCPS = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_cps",
		Help:      "Service connections per second",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServiceBpsIn Incoming bytes per second
	ServiceBpsIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_bps_in",
		Help:      "Incoming bytes per second",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServiceBpsOut Outgoing bytes per second
	ServiceBpsOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_bps_out",
		Help:      "Outgoing bytes per second",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ControllerIpvsServices Number of ipvs services in the instance
	ControllerIpvsServices = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_ipvs_services",
		Help:      "Number of ipvs services in the instance",
	})
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

	srv := &http.Server{
		Addr:              mc.MetricsAddr + ":" + strconv.Itoa(int(mc.MetricsPort)),
		Handler:           http.DefaultServeMux,
		ReadHeaderTimeout: 5 * time.Second}

	// add prometheus handler on metrics path
	http.Handle(mc.MetricsPath, Handler())

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

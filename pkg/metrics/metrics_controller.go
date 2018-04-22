package metrics

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/context"
	"k8s.io/client-go/kubernetes"
)

const (
	namespace = "kube_router"
)

var (
	ServiceTotalConn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_total_connections",
		Help:      "Total incoming connections made",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	ServicePacketsIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_packets_in",
		Help:      "Total incoming packets",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	ServicePacketsOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_packets_out",
		Help:      "Total outgoing packets",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	ServiceBytesIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_bytes_in",
		Help:      "Total incoming bytes",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	ServiceBytesOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_bytes_out",
		Help:      "Total outgoing bytes",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	ServicePpsIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_pps_in",
		Help:      "Incoming packets per second",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	ServicePpsOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_pps_out",
		Help:      "Outgoing packets per second",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	ServiceCPS = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_cps",
		Help:      "Service connections per second",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	ServiceBpsIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_bps_in",
		Help:      "Incoming bytes per second",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	ServiceBpsOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_bps_out",
		Help:      "Outgoing bytes per second",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	ControllerIpvsServices = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_ipvs_services",
		Help:      "Number of ipvs services in the instance",
	}, []string{})
	ControllerIptablesSyncTime = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_iptables_sync_time",
		Help:      "Time it took for controller to sync iptables",
	}, []string{})
	ControllerPublishMetricsTime = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_publish_metrics_time",
		Help:      "Time it took to publish metrics",
	}, []string{})
	ControllerIpvsServicesSyncTime = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_ipvs_services_sync_time",
		Help:      "Time it took for controller to sync ipvs services",
	}, []string{})
	ControllerBPGpeers = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_bgp_peers",
		Help:      "BGP peers in the runtime configuration",
	}, []string{})
	ControllerBGPInternalPeersSyncTime = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_bgp_internal_peers_sync_time",
		Help:      "Time it took to sync internal bgp peers",
	}, []string{})
	ControllerBGPadvertisementsReceived = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_bgp_advertisements_received",
		Help:      "Time it took to sync internal bgp peers",
	}, []string{})
	ControllerIpvsMetricsExportTime = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_ipvs_metrics_export_time",
		Help:      "Time it took to export metrics",
	}, []string{})
)

// MetricsController Holds settings for the metrics controller
type MetricsController struct {
	MetricsPath string
	MetricsPort uint16
	mu          sync.Mutex
	nodeIP      net.IP
}

// Run prometheus metrics controller
func (mc *MetricsController) Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) error {
	t := time.NewTicker(3 * time.Second)
	defer wg.Done()
	glog.Info("Starting metrics controller")

	// register metrics for this controller
	prometheus.MustRegister(ControllerIpvsMetricsExportTime)

	srv := &http.Server{Addr: ":" + strconv.Itoa(int(mc.MetricsPort)), Handler: http.DefaultServeMux}

	// add prometheus handler on metrics path
	http.Handle(mc.MetricsPath, promhttp.Handler())

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			// cannot panic, because this probably is an intentional close
			glog.Errorf("Metrics controller error: %s", err)
		}
	}()
	for {
		healthcheck.SendHeartBeat(healthChan, "MC")
		select {
		case <-stopCh:
			glog.Infof("Shutting down metrics controller")
			if err := srv.Shutdown(context.Background()); err != nil {
				glog.Errorf("could not shutdown: %v", err)
			}
			return nil
		case <-t.C:
			glog.V(4).Info("Metrics controller tick")
		}
	}
}

// NewMetricsController returns new MetricController object
func NewMetricsController(clientset kubernetes.Interface, config *options.KubeRouterConfig) (*MetricsController, error) {
	mc := MetricsController{}
	mc.MetricsPath = config.MetricsPath
	mc.MetricsPort = config.MetricsPort
	return &mc, nil
}

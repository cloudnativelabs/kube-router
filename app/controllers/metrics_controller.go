package controllers

import (
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/app/options"
	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/context"
	"k8s.io/client-go/kubernetes"
)

var (
	serviceTotalConn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_total_connections",
		Help:      "Total incoming conntections made",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	servicePacketsIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_packets_in",
		Help:      "Total incoming packets",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	servicePacketsOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_packets_out",
		Help:      "Total outoging packets",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	serviceBytesIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_bytes_in",
		Help:      "Total incoming bytes",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	serviceBytesOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_bytes_out",
		Help:      "Total outgoing bytes",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	servicePpsIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_pps_in",
		Help:      "Incoming packets per second",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	servicePpsOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_pps_out",
		Help:      "Outoging packets per second",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	serviceCPS = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_cps",
		Help:      "Service connections per second",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	serviceBpsIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_bps_in",
		Help:      "Incoming bytes per second",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	serviceBpsOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_bps_out",
		Help:      "Outoging bytes per second",
	}, []string{"namespace", "service_name", "service_vip", "protocol", "port"})
	controllerIpvsServices = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_ipvs_services",
		Help:      "Number of ipvs services in the instance",
	}, []string{})
	controllerIptablesSyncTime = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_iptables_sync_time",
		Help:      "Time it took for controller to sync iptables",
	}, []string{})
	controllerPublishMetricsTime = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_publish_metrics_time",
		Help:      "Time it took to publish metrics",
	}, []string{})
	controllerIpvsServicesSyncTime = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_ipvs_services_sync_time",
		Help:      "Time it took for controller to sync ipvs services",
	}, []string{})
	controllerBPGpeers = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_bgp_peers",
		Help:      "BGP peers in the runtime configuration",
	}, []string{})
	controllerBGPInternalPeersSyncTime = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_bgp_internal_peers_sync_time",
		Help:      "Time it took to sync internal bgp peers",
	}, []string{})
	controllerBGPadvertisementsReceived = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_bgp_advertisements_received",
		Help:      "Time it took to sync internal bgp peers",
	}, []string{})
)

// Holds settings for the metrics controller
type MetricsController struct {
	MetricsPort int
	MetricsPath string
}

// Run prometheus metrics controller
func (mc *MetricsController) Run(stopCh <-chan struct{}, wg *sync.WaitGroup) error {
	defer wg.Done()
	glog.Info("Starting metrics controller")
	// register metrics
	prometheus.MustRegister(controllerBGPadvertisementsReceived)
	prometheus.MustRegister(controllerBGPInternalPeersSyncTime)
	prometheus.MustRegister(controllerBPGpeers)
	prometheus.MustRegister(controllerIptablesSyncTime)
	prometheus.MustRegister(controllerIpvsServices)
	prometheus.MustRegister(controllerIpvsServicesSyncTime)
	prometheus.MustRegister(serviceBpsIn)
	prometheus.MustRegister(serviceBpsOut)
	prometheus.MustRegister(serviceBytesIn)
	prometheus.MustRegister(serviceBytesOut)
	prometheus.MustRegister(serviceCPS)
	prometheus.MustRegister(servicePacketsIn)
	prometheus.MustRegister(servicePacketsOut)
	prometheus.MustRegister(servicePpsIn)
	prometheus.MustRegister(servicePpsOut)
	prometheus.MustRegister(serviceTotalConn)

	srv := &http.Server{Addr: ":" + strconv.Itoa(mc.MetricsPort), Handler: http.DefaultServeMux}

	go func() {
		<-stopCh
		glog.Info("Shutting down metrics controller")
		if err := srv.Shutdown(context.Background()); err != nil {
			glog.Errorf("could not shutdown: %v", err)
		}
	}()

	// add prometheus handler on metrics path
	http.Handle(mc.MetricsPath, promhttp.Handler())

	err := srv.ListenAndServe()
	if err != http.ErrServerClosed {
		glog.Fatalf("Coult not start metrics controller: %s\n", err)
	}

	glog.Info("Metrics controller stopped")
	return nil
}

func NewMetricsController(clientset *kubernetes.Clientset, config *options.KubeRouterConfig) (*MetricsController, error) {
	mc := MetricsController{}
	mc.MetricsPort = config.MetricsPort
	mc.MetricsPath = config.MetricsPath
	rand.Seed(time.Now().UnixNano())
	return &mc, nil
}

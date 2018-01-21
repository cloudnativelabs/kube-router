package controllers

import (
	"errors"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/app/options"
	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/context"
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
	syncPeriod  time.Duration
}

// Run prometheus metrics controller
func (mc *MetricsController) Run(stopCh <-chan struct{}, wg *sync.WaitGroup) error {
	t := time.NewTicker(mc.syncPeriod)
	defer t.Stop()
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
	
	go err := srv.ListenAndServe()
	if err != http.ErrServerClosed {
		glog.Fatalf("Coult not start metrics controller: %s\n", err)
	}
	
	for {
		select {
		case <-stopCh:
			glog.Infof("Shutting down metrics controller")
			return
		default:
		}
		
		mc.sync()
		
		select {
		case <-stopCh:
			glog.Info("Shutting down metrics controller")
			return
		case <-t.C:
		}
	}
	return nil
}

func (mc *MetricsController) publishMetrics(serviceInfoMap serviceInfoMap) error {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		glog.V(2).Infof("Publishing Prometheus metrics took %v", endTime)
	}()
	ipvsSvcs, err := h.GetServices()
	if err != nil {
		return errors.New("Failed to list IPVS services: " + err.Error())
	}

	glog.V(1).Info("Publishing Prometheus metrics")
	for _, svc := range serviceInfoMap {
		var protocol uint16
		var pushMetric bool
		var svcVip string

		switch aProtocol := svc.protocol; aProtocol {
		case "tcp":
			protocol = syscall.IPPROTO_TCP
		case "udp":
			protocol = syscall.IPPROTO_UDP
		default:
			protocol = syscall.IPPROTO_NONE
		}
		for _, ipvsSvc := range ipvsSvcs {

			switch svcAddress := ipvsSvc.Address.String(); svcAddress {
			case svc.clusterIP.String():
				if protocol == ipvsSvc.Protocol && uint16(svc.port) == ipvsSvc.Port {
					pushMetric = true
					svcVip = svc.clusterIP.String()
				} else {
					pushMetric = false
				}
			case nsc.nodeIP.String():
				if protocol == ipvsSvc.Protocol && uint16(svc.port) == ipvsSvc.Port {
					pushMetric = true
					svcVip = nsc.nodeIP.String()
				} else {
					pushMetric = false
				}
			default:
				svcVip = ""
				pushMetric = false
			}

			if pushMetric {
				glog.V(3).Infof("Publishing metrics for %s/%s (%s:%d/%s)", svc.namespace, svc.name, svcVip, svc.port, svc.protocol)
				serviceBpsIn.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.BPSIn))
				serviceBpsOut.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.BPSOut))
				serviceBytesIn.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.BytesIn))
				serviceBytesOut.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.BytesOut))
				serviceCPS.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.CPS))
				servicePacketsIn.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.PacketsIn))
				servicePacketsOut.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.PacketsOut))
				servicePpsIn.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.PPSIn))
				servicePpsOut.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.PPSOut))
				serviceTotalConn.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.Connections))
				controllerIpvsServices.WithLabelValues().Set(float64(len(ipvsSvcs)))
			}
		}
	}
	return nil
}

func (mc *MetricsController) sync() {
	mc.serviceMap = buildServicesInfo()
	mc.endpointsMap = buildEndpointsInfo()
	mc.publishMetrics(mc.serviceMap)
}

func NewMetricsController(config *options.KubeRouterConfig) (*MetricsController, error) {
	mc := MetricsController{}
	mc.MetricsPort = config.MetricsPort
	mc.MetricsPath = config.MetricsPath
	mc.syncPeriod = config.MetricsSyncPeriod
	rand.Seed(time.Now().UnixNano())
	return &mc, nil
}

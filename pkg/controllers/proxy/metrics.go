package proxy

import (
	"strconv"
	"time"

	"github.com/ccoveille/go-safecast"
	"github.com/cloudnativelabs/kube-router/v2/pkg/metrics"
	"github.com/moby/ipvs"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

type metricsServiceMapKey struct {
	ip       string
	uPort    uint16
	protocol uint16
}

type metricsServiceMap map[metricsServiceMapKey]*serviceInfo

// getMetricsServiceMap builds a structure suitable for quick matching services
func (nsc *NetworkServicesController) getMetricsServiceMap() metricsServiceMap {
	if serviceMapPtr := nsc.metricsServiceMap.Load(); serviceMapPtr != nil {
		return *serviceMapPtr
	}

	var err error
	serviceMap := metricsServiceMap{}

	for _, svc := range nsc.getServiceMap() {
		key := metricsServiceMapKey{}
		key.uPort, err = safecast.Convert[uint16](svc.port)
		if err != nil {
			klog.Errorf("failed to convert port %d to uint16: %v", svc.port, err)
			continue
		}
		key.protocol = convertSvcProtoToSysCallProto(svc.protocol)

		for _, ip := range svc.clusterIPs {
			key.ip = ip
			serviceMap[key] = svc
		}
		for _, ip := range svc.externalIPs {
			key.ip = ip
			serviceMap[key] = svc
		}
		for _, ip := range svc.loadBalancerIPs {
			key.ip = ip
			serviceMap[key] = svc
		}
		if svc.nodePort != 0 {
			key.ip = nsc.krNode.GetPrimaryNodeIP().String()
			key.uPort, err = safecast.Convert[uint16](svc.nodePort)
			if err != nil {
				klog.Errorf("failed to convert nodePort %d to uint16: %v", svc.nodePort, err)
				continue
			}
			serviceMap[key] = svc
		}
	}

	nsc.metricsServiceMap.Store(&serviceMap)

	return serviceMap
}

func (m metricsServiceMap) lookupService(ip string, uPort uint16, protocol uint16) *serviceInfo {
	key := metricsServiceMapKey{
		ip:       ip,
		uPort:    uPort,
		protocol: protocol,
	}

	return m[key]
}

func (*NetworkServicesController) Describe(ch chan<- *prometheus.Desc) {
	ch <- metrics.ServiceBpsIn
	ch <- metrics.ServiceBpsOut
	ch <- metrics.ServiceBytesIn
	ch <- metrics.ServiceBytesOut
	ch <- metrics.ServiceCPS
	ch <- metrics.ServicePacketsIn
	ch <- metrics.ServicePacketsOut
	ch <- metrics.ServicePpsIn
	ch <- metrics.ServicePpsOut
	ch <- metrics.ServiceTotalConn
	ch <- metrics.ControllerIpvsServices
}

func (nsc *NetworkServicesController) Collect(ch chan<- prometheus.Metric) {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		klog.V(2).Infof("Publishing IPVS metrics took %v", endTime)
		if nsc.MetricsEnabled {
			metrics.ControllerIpvsMetricsExportTime.Observe(endTime.Seconds())
		}
	}()

	serviceMap := nsc.getMetricsServiceMap()

	ipvsHandle, err := ipvs.New("")
	if err != nil {
		klog.Errorf("failed to initialize ipvs handle: %v", err)
		return
	}
	defer ipvsHandle.Close()

	ipvsSvcs, err := ipvsHandle.GetServices()
	if err != nil {
		klog.Errorf("failed to list IPVS services: %v", err)
		return
	}

	klog.V(1).Info("Publishing IPVS metrics")
	for _, ipvsSvc := range ipvsSvcs {
		ip := ipvsSvc.Address.String()
		svc := serviceMap.lookupService(ip, ipvsSvc.Port, ipvsSvc.Protocol)

		if svc == nil {
			continue
		}

		klog.V(3).Infof("Publishing metrics for %s/%s (%s:%d/%s)",
			svc.namespace, svc.name, ip, ipvsSvc.Port, svc.protocol)

		labelValues := []string{
			svc.namespace,
			svc.name,
			ip,
			svc.protocol,
			strconv.Itoa(int(ipvsSvc.Port)),
		}

		ch <- prometheus.MustNewConstMetric(
			metrics.ServiceBpsIn,
			prometheus.GaugeValue,
			float64(ipvsSvc.Stats.BPSIn),
			labelValues...,
		)

		ch <- prometheus.MustNewConstMetric(
			metrics.ServiceBpsOut,
			prometheus.GaugeValue,
			float64(ipvsSvc.Stats.BPSOut),
			labelValues...,
		)

		ch <- prometheus.MustNewConstMetric(
			metrics.ServiceBytesIn,
			prometheus.CounterValue,
			float64(ipvsSvc.Stats.BytesIn),
			labelValues...,
		)

		ch <- prometheus.MustNewConstMetric(
			metrics.ServiceBytesOut,
			prometheus.CounterValue,
			float64(ipvsSvc.Stats.BytesOut),
			labelValues...,
		)

		ch <- prometheus.MustNewConstMetric(
			metrics.ServiceCPS,
			prometheus.GaugeValue,
			float64(ipvsSvc.Stats.CPS),
			labelValues...,
		)

		ch <- prometheus.MustNewConstMetric(
			metrics.ServicePacketsIn,
			prometheus.CounterValue,
			float64(ipvsSvc.Stats.PacketsIn),
			labelValues...,
		)

		ch <- prometheus.MustNewConstMetric(
			metrics.ServicePacketsOut,
			prometheus.CounterValue,
			float64(ipvsSvc.Stats.PacketsOut),
			labelValues...,
		)

		ch <- prometheus.MustNewConstMetric(
			metrics.ServicePpsIn,
			prometheus.GaugeValue,
			float64(ipvsSvc.Stats.PPSIn),
			labelValues...,
		)

		ch <- prometheus.MustNewConstMetric(
			metrics.ServicePpsOut,
			prometheus.GaugeValue,
			float64(ipvsSvc.Stats.PPSOut),
			labelValues...,
		)

		ch <- prometheus.MustNewConstMetric(
			metrics.ServiceTotalConn,
			prometheus.CounterValue,
			float64(ipvsSvc.Stats.Connections),
			labelValues...,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		metrics.ControllerIpvsServices,
		prometheus.GaugeValue,
		float64(len(ipvsSvcs)),
	)
}

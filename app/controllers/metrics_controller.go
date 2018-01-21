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
	"k8s.io/client-go/kubernetes"
)

type MetricsController struct {
	MetricsPort int
	MetricsPath string
}

func (mc *MetricsController) Run(stopCh <-chan struct{}, wg *sync.WaitGroup) error {

	glog.Info("Starting metrics controller")
	// register metrics
	prometheus.MustRegister(controllerBGPadvertisementsReceived)
	prometheus.MustRegister(controllerBGPInternalPeersSyncTime)
	prometheus.MustRegister(controllerBPGpeers)
	prometheus.MustRegister(controllerIptablesSyncTime)
	prometheus.MustRegister(controllerIpvsServices)
	prometheus.MustRegister(controllerIpvsServicesSyncTime)
	prometheus.MustRegister(controllerPublishMetricsTime)
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

	http.Handle(mc.MetricsPath, promhttp.Handler())
	go http.ListenAndServe(":"+strconv.Itoa(mc.MetricsPort), nil)

	// loop forever unitl notified to stop on stopCh
	for {
		select {
		case <-stopCh:
			glog.Info("Shutting down metrics controller")
			return nil
		default:
		}
	}
}

func NewMetricsController(clientset *kubernetes.Clientset, config *options.KubeRouterConfig) (*MetricsController, error) {
	var err error
	mc := MetricsController{}
	mc.MetricsPort = config.MetricsPort
	mc.MetricsPath = config.MetricsPath
	mc.client = clientset
	rand.Seed(time.Now().UnixNano())
	return &mc, nil
}

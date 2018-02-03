package app

import (
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cloudnativelabs/kube-router/app/controllers"
	"github.com/cloudnativelabs/kube-router/app/options"
	"github.com/cloudnativelabs/kube-router/app/watchers"
	"github.com/golang/glog"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// KubeRouter holds the information needed to run server
type KubeRouter struct {
	Client *kubernetes.Clientset
	Config *options.KubeRouterConfig
}

// NewKubeRouterDefault returns a KubeRouter object
func NewKubeRouterDefault(config *options.KubeRouterConfig) (*KubeRouter, error) {

	var clientconfig *rest.Config
	var err error
	// Use out of cluster config if the URL or kubeconfig have been specified. Otherwise use incluster config.
	if len(config.Master) != 0 || len(config.Kubeconfig) != 0 {
		clientconfig, err = clientcmd.BuildConfigFromFlags(config.Master, config.Kubeconfig)
		if err != nil {
			return nil, errors.New("Failed to build configuration from CLI: " + err.Error())
		}
	} else {
		clientconfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, errors.New("unable to initialize inclusterconfig: " + err.Error())
		}
	}

	clientset, err := kubernetes.NewForConfig(clientconfig)
	if err != nil {
		return nil, errors.New("Failed to create Kubernetes client: " + err.Error())
	}

	return &KubeRouter{Client: clientset, Config: config}, nil
}

// CleanupConfigAndExit performs Cleanup on all three controllers
func CleanupConfigAndExit() {
	npc := controllers.NetworkPolicyController{}
	npc.Cleanup()

	nsc := controllers.NetworkServicesController{}
	nsc.Cleanup()

	nrc := controllers.NetworkRoutingController{}
	nrc.Cleanup()
}

// start API watchers to get notification on changes
func (kr *KubeRouter) startApiWatchers() error {

	var err error

	_, err = watchers.StartPodWatcher(kr.Client, kr.Config.ConfigSyncPeriod)
	if err != nil {
		return errors.New("Failed to launch pod api watcher: " + err.Error())
	}

	_, err = watchers.StartEndpointsWatcher(kr.Client, kr.Config.ConfigSyncPeriod)
	if err != nil {
		return errors.New("Failed to launch endpoint api watcher: " + err.Error())
	}

	_, err = watchers.StartNetworkPolicyWatcher(kr.Client, kr.Config.ConfigSyncPeriod)
	if err != nil {
		return errors.New("Failed to launch network policy api watcher: " + err.Error())
	}

	_, err = watchers.StartNamespaceWatcher(kr.Client, kr.Config.ConfigSyncPeriod)
	if err != nil {
		return errors.New("Failed to launch namespace api watcher: " + err.Error())
	}

	_, err = watchers.StartServiceWatcher(kr.Client, kr.Config.ConfigSyncPeriod)
	if err != nil {
		return errors.New("Failed to launch service api watcher: " + err.Error())
	}

	_, err = watchers.StartNodeWatcher(kr.Client, kr.Config.ConfigSyncPeriod)
	if err != nil {
		return errors.New("Failed to launch nodes api watcher: " + err.Error())
	}

	return nil
}

func (kr *KubeRouter) stopApiWatchers() {
	watchers.StopPodWatcher()
	watchers.StopEndpointsWatcher()
	watchers.StopNetworkPolicyWatcher()
	watchers.StopNamespaceWatcher()
	watchers.StopServiceWatcher()
	watchers.StopNodeWatcher()
}

// Run starts the controllers and waits forever till we get SIGINT or SIGTERM
func (kr *KubeRouter) Run() error {
	var err error
	var wg sync.WaitGroup
	healthChan := make(chan *controllers.ControllerHeartbeat, 10)

	stopCh := make(chan struct{})

	err = kr.startApiWatchers()
	if err != nil {
		return errors.New("Failed to start API watchers: " + err.Error())
	}

	if !(kr.Config.RunFirewall || kr.Config.RunServiceProxy || kr.Config.RunRouter) {
		glog.Info("Router, Firewall or Service proxy functionality must be specified. Exiting!")
		os.Exit(0)
	}

	if (kr.Config.HealthPort > 0) && (kr.Config.HealthPort <= 65535) {
		hc, err := controllers.NewHealthController(kr.Config)
		if err != nil {
			return errors.New("Failed to create health controller: " + err.Error())
		}
		wg.Add(1)
		go hc.Run(healthChan, stopCh, &wg)
	}

	if (kr.Config.MetricsPort > 0) && (kr.Config.MetricsPort <= 65535) {
		kr.Config.MetricsEnabled = true
		mc, err := controllers.NewMetricsController(kr.Client, kr.Config)
		if err != nil {
			return errors.New("Failed to create metrics controller: " + err.Error())
		}
		wg.Add(1)
		go mc.Run(healthChan, stopCh, &wg)

	} else if kr.Config.MetricsPort > 65535 {
		glog.Errorf("Metrics port must be over 0 and under 65535, given port: %d", kr.Config.MetricsPort)
		kr.Config.MetricsEnabled = false
	} else {
		kr.Config.MetricsEnabled = false
	}

	if kr.Config.RunFirewall {
		npc, err := controllers.NewNetworkPolicyController(kr.Client, kr.Config)
		if err != nil {
			return errors.New("Failed to create network policy controller: " + err.Error())
		}

		wg.Add(1)
		go npc.Run(healthChan, stopCh, &wg)
	}

	if kr.Config.RunRouter {
		nrc, err := controllers.NewNetworkRoutingController(kr.Client, kr.Config)
		if err != nil {
			return errors.New("Failed to create network routing controller: " + err.Error())
		}

		wg.Add(1)
		go nrc.Run(healthChan, stopCh, &wg)
	}

	if kr.Config.RunServiceProxy {
		nsc, err := controllers.NewNetworkServicesController(kr.Client, kr.Config)
		if err != nil {
			return errors.New("Failed to create network services controller: " + err.Error())
		}

		wg.Add(1)
		go nsc.Run(healthChan, stopCh, &wg)
	}

	// Handle SIGINT and SIGTERM
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	glog.Infof("Shutting down the controllers")
	close(stopCh)

	kr.stopApiWatchers()

	wg.Wait()
	return nil
}

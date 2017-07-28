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

type KubeRouter struct {
	Client *kubernetes.Clientset
	Config *options.KubeRouterConfig
}

func NewKubeRouterDefault(config *options.KubeRouterConfig) (*KubeRouter, error) {

	var clientconfig *rest.Config
	var err error
	// Use out of cluster config if the URL or kubeconfig have been specified. Otherwise use incluster config.
	if len(config.Master) != 0 && len(config.Kubeconfig) != 0 {
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

func (kr *KubeRouter) Run() error {

	var err error
	var nscStopCh, npcStopCh, nrcStopCh chan struct{}
	var wg sync.WaitGroup

	err = kr.startApiWatchers()
	if err != nil {
		return errors.New("Failed to start API watchers: " + err.Error())
	}

	if !(kr.Config.RunFirewall || kr.Config.RunServiceProxy || kr.Config.RunRouter) {
		glog.Infof("None of router, firewall, service proxy functionality was specified to be run. So exiting")
		os.Exit(0)
	}

	if kr.Config.RunFirewall {
		npc, err := controllers.NewNetworkPolicyController(kr.Client, kr.Config)
		if err != nil {
			return errors.New("Failed to create network policy controller: " + err.Error())
		}
		npcStopCh = make(chan struct{})
		wg.Add(1)
		go npc.Run(npcStopCh, &wg)
	}

	if kr.Config.RunRouter {
		nrc, err := controllers.NewNetworkRoutingController(kr.Client, kr.Config)
		if err != nil {
			return errors.New("Failed to create network routing controller: " + err.Error())
		}
		nrcStopCh = make(chan struct{})
		wg.Add(1)
		go nrc.Run(nrcStopCh, &wg)
	}

	if kr.Config.RunServiceProxy {
		nsc, err := controllers.NewNetworkServicesController(kr.Client, kr.Config)
		if err != nil {
			return errors.New("Failed to create network services controller: " + err.Error())
		}
		nscStopCh = make(chan struct{})
		wg.Add(1)
		go nsc.Run(nscStopCh, &wg)
	}

	// Handle SIGINT and SIGTERM
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	glog.Infof("Shutting down the controllers")
	if kr.Config.RunServiceProxy {
		nscStopCh <- struct{}{}
	}
	if kr.Config.RunFirewall {
		npcStopCh <- struct{}{}
	}
	if kr.Config.RunRouter {
		nrcStopCh <- struct{}{}
	}

	kr.stopApiWatchers()

	wg.Wait()
	return nil
}

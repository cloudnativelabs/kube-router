package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/cloudnativelabs/kube-router/pkg/controllers/netpol"
	"github.com/cloudnativelabs/kube-router/pkg/controllers/proxy"
	"github.com/cloudnativelabs/kube-router/pkg/controllers/routing"
	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/golang/glog"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"time"
)

// These get set at build time via -ldflags magic
var version string
var buildDate string

// KubeRouter holds the information needed to run server
type KubeRouter struct {
	Client kubernetes.Interface
	Config *options.KubeRouterConfig
}

// NewKubeRouterDefault returns a KubeRouter object
func NewKubeRouterDefault(config *options.KubeRouterConfig) (*KubeRouter, error) {

	var clientconfig *rest.Config
	var err error
	PrintVersion(true)
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
	npc := netpol.NetworkPolicyController{}
	npc.Cleanup()

	nsc := proxy.NetworkServicesController{}
	nsc.Cleanup()

	nrc := routing.NetworkRoutingController{}
	nrc.Cleanup()
}

// Run starts the controllers and waits forever till we get SIGINT or SIGTERM
func (kr *KubeRouter) Run() error {
	var err error
	var wg sync.WaitGroup
	healthChan := make(chan *healthcheck.ControllerHeartbeat, 10)
	defer close(healthChan)
	stopCh := make(chan struct{})

	if !(kr.Config.RunFirewall || kr.Config.RunServiceProxy || kr.Config.RunRouter) {
		glog.Info("Router, Firewall or Service proxy functionality must be specified. Exiting!")
		os.Exit(0)
	}

	hc, err := healthcheck.NewHealthController(kr.Config)
	if err != nil {
		return errors.New("Failed to create health controller: " + err.Error())
	}
	wg.Add(1)
	go hc.RunServer(stopCh, &wg)

	informerFactory := informers.NewSharedInformerFactory(kr.Client, 0)
	svcInformer := informerFactory.Core().V1().Services().Informer()
	epInformer := informerFactory.Core().V1().Endpoints().Informer()
	podInformer := informerFactory.Core().V1().Pods().Informer()
	nodeInformer := informerFactory.Core().V1().Nodes().Informer()
	nsInformer := informerFactory.Core().V1().Namespaces().Informer()
	npInformer := informerFactory.Networking().V1().NetworkPolicies().Informer()
	informerFactory.Start(stopCh)

	err = kr.CacheSyncOrTimeout(informerFactory, stopCh)
	if err != nil {
		return errors.New("Failed to synchronize cache: " + err.Error())
	}

	hc.SetAlive()
	wg.Add(1)
	go hc.RunCheck(healthChan, stopCh, &wg)

	if (kr.Config.MetricsPort > 0) && (kr.Config.MetricsPort <= 65535) {
		kr.Config.MetricsEnabled = true
		mc, err := metrics.NewMetricsController(kr.Client, kr.Config)
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
		npc, err := netpol.NewNetworkPolicyController(kr.Client,
			kr.Config, podInformer, npInformer, nsInformer)
		if err != nil {
			return errors.New("Failed to create network policy controller: " + err.Error())
		}

		podInformer.AddEventHandler(npc.PodEventHandler)
		nsInformer.AddEventHandler(npc.NamespaceEventHandler)
		npInformer.AddEventHandler(npc.NetworkPolicyEventHandler)

		wg.Add(1)
		go npc.Run(healthChan, stopCh, &wg)
	}

	if kr.Config.BGPGracefulRestart {
		if kr.Config.BGPGracefulRestartTime > time.Second*4095 {
			return errors.New("BGPGracefuleRestartTime should be less than 4095 seconds")
		}
		if kr.Config.BGPGracefulRestartTime <= 0 {
			return errors.New("BGPGracefuleRestartTime must be positive")
		}

		if kr.Config.BGPGracefulRestartDeferralTime > time.Hour*18 {
			return errors.New("BGPGracefuleRestartDeferralTime should be less than 18 hours")
		}
		if kr.Config.BGPGracefulRestartDeferralTime <= 0 {
			return errors.New("BGPGracefuleRestartDeferralTime must be positive")
		}
	}

	if kr.Config.RunRouter {
		nrc, err := routing.NewNetworkRoutingController(kr.Client, kr.Config, nodeInformer, svcInformer, epInformer)
		if err != nil {
			return errors.New("Failed to create network routing controller: " + err.Error())
		}

		nodeInformer.AddEventHandler(nrc.NodeEventHandler)
		svcInformer.AddEventHandler(nrc.ServiceEventHandler)
		epInformer.AddEventHandler(nrc.EndpointsEventHandler)

		wg.Add(1)
		go nrc.Run(healthChan, stopCh, &wg)
	}

	if kr.Config.RunServiceProxy {
		nsc, err := proxy.NewNetworkServicesController(kr.Client, kr.Config,
			svcInformer, epInformer, podInformer)
		if err != nil {
			return errors.New("Failed to create network services controller: " + err.Error())
		}

		svcInformer.AddEventHandler(nsc.ServiceEventHandler)
		epInformer.AddEventHandler(nsc.EndpointsEventHandler)

		wg.Add(1)
		go nsc.Run(healthChan, stopCh, &wg)
	}

	// Handle SIGINT and SIGTERM
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	glog.Infof("Shutting down the controllers")
	close(stopCh)

	wg.Wait()
	return nil
}

// CacheSync performs cache synchronization under timeout limit
func (kr *KubeRouter) CacheSyncOrTimeout(informerFactory informers.SharedInformerFactory, stopCh <-chan struct{}) error {
	syncOverCh := make(chan struct{})
	go func() {
		informerFactory.WaitForCacheSync(stopCh)
		close(syncOverCh)
	}()

	select {
	case <-time.After(kr.Config.CacheSyncTimeout):
		return errors.New(kr.Config.CacheSyncTimeout.String() + " timeout")
	case <-syncOverCh:
		return nil
	}
}

func PrintVersion(logOutput bool) {
	output := fmt.Sprintf("Running %v version %s, built on %s, %s\n", os.Args[0], version, buildDate, runtime.Version())

	if !logOutput {
		fmt.Fprintf(os.Stderr, output)
	} else {
		glog.Info(output)
	}
}

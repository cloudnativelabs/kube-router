package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/controllers/lballoc"
	"github.com/cloudnativelabs/kube-router/v2/pkg/controllers/netpol"
	"github.com/cloudnativelabs/kube-router/v2/pkg/controllers/proxy"
	"github.com/cloudnativelabs/kube-router/v2/pkg/controllers/routing"
	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/v2/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/version"
	"k8s.io/klog/v2"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const healthControllerChannelLength = 10

// KubeRouter holds the information needed to run server
type KubeRouter struct {
	Client kubernetes.Interface
	Config *options.KubeRouterConfig
}

// NewKubeRouterDefault returns a KubeRouter object
func NewKubeRouterDefault(config *options.KubeRouterConfig) (*KubeRouter, error) {
	var clientconfig *rest.Config
	var err error
	version.PrintVersion(true)
	version.PrintVersionMessages(true)
	// Use out of cluster config if the URL or kubeconfig have been specified. Otherwise use incluster config.
	if len(config.Master) != 0 || len(config.Kubeconfig) != 0 {
		clientconfig, err = clientcmd.BuildConfigFromFlags(config.Master, config.Kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build configuration from CLI: %v", err)
		}
	} else {
		clientconfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("unable to initialize inclusterconfig: %v", err)
		}
	}

	clientconfig.Timeout = config.KubeClientTimeout
	klog.V(1).Infof("Using timeout %s for calls to api server.", clientconfig.Timeout.String())
	clientset, err := kubernetes.NewForConfig(clientconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %v", err)
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
	var ipsetMutex sync.Mutex
	var wg sync.WaitGroup

	if !(kr.Config.RunFirewall || kr.Config.RunServiceProxy || kr.Config.RunRouter) {
		klog.Info("Router, Firewall or Service proxy functionality must be specified. Exiting!")
		os.Exit(0)
	}

	healthChan := make(chan *healthcheck.ControllerHeartbeat, healthControllerChannelLength)
	defer close(healthChan)
	stopCh := make(chan struct{})

	hc, err := healthcheck.NewHealthController(kr.Config)
	if err != nil {
		return fmt.Errorf("failed to create health controller: %v", err)
	}
	wg.Add(1)
	go hc.RunServer(stopCh, &wg)

	informerFactory := informers.NewSharedInformerFactory(kr.Client, 0)
	svcInformer := informerFactory.Core().V1().Services().Informer()
	epInformer := informerFactory.Core().V1().Endpoints().Informer()
	epSliceInformer := informerFactory.Discovery().V1().EndpointSlices().Informer()
	podInformer := informerFactory.Core().V1().Pods().Informer()
	nodeInformer := informerFactory.Core().V1().Nodes().Informer()
	nsInformer := informerFactory.Core().V1().Namespaces().Informer()
	npInformer := informerFactory.Networking().V1().NetworkPolicies().Informer()
	informerFactory.Start(stopCh)

	err = kr.CacheSyncOrTimeout(informerFactory, stopCh)
	if err != nil {
		return fmt.Errorf("failed to synchronize cache: %v", err)
	}

	hc.SetAlive()
	wg.Add(1)
	go hc.RunCheck(healthChan, stopCh, &wg)

	if kr.Config.MetricsPort > 0 && kr.Config.MetricsPort < 65535 {
		kr.Config.MetricsEnabled = true
		mc, err := metrics.NewMetricsController(kr.Config)
		if err != nil {
			return fmt.Errorf("failed to create metrics controller: %v", err)
		}
		wg.Add(1)
		go mc.Run(healthChan, stopCh, &wg)

	} else {
		klog.Infof("Metrics port must be over 0 and under 65535 in order to be enabled, given port: %d",
			kr.Config.MetricsPort)
		klog.Infof("Disabling metrics for kube-router, set --metrics-port properly in order to enable")
		kr.Config.MetricsEnabled = false
	}

	if kr.Config.BGPGracefulRestart {
		if kr.Config.BGPGracefulRestartTime > time.Second*4095 {
			return errors.New("BGPGracefulRestartTime should be less than 4095 seconds")
		}
		if kr.Config.BGPGracefulRestartTime <= 0 {
			return errors.New("BGPGracefulRestartTime must be positive")
		}

		if kr.Config.BGPGracefulRestartDeferralTime > time.Hour*18 {
			return errors.New("BGPGracefulRestartDeferralTime should be less than 18 hours")
		}
		if kr.Config.BGPGracefulRestartDeferralTime <= 0 {
			return errors.New("BGPGracefulRestartDeferralTime must be positive")
		}
	}

	if kr.Config.RunRouter {
		nrc, err := routing.NewNetworkRoutingController(kr.Client, kr.Config,
			nodeInformer, svcInformer, epInformer, &ipsetMutex)
		if err != nil {
			return fmt.Errorf("failed to create network routing controller: %v", err)
		}

		_, err = nodeInformer.AddEventHandler(nrc.NodeEventHandler)
		if err != nil {
			return fmt.Errorf("failed to add NodeEventHandler: %v", err)
		}
		_, err = svcInformer.AddEventHandler(nrc.ServiceEventHandler)
		if err != nil {
			return fmt.Errorf("failed to add ServiceEventHandler: %v", err)
		}
		_, err = epInformer.AddEventHandler(nrc.EndpointsEventHandler)
		if err != nil {
			return fmt.Errorf("failed to add EndpointsEventHandler: %v", err)
		}

		wg.Add(1)
		go nrc.Run(healthChan, stopCh, &wg)

		// wait for the pod networking related firewall rules to be setup before network policies
		if kr.Config.RunFirewall {
			nrc.CNIFirewallSetup.L.Lock()
			nrc.CNIFirewallSetup.Wait()
			nrc.CNIFirewallSetup.L.Unlock()
		}
	}

	if kr.Config.RunServiceProxy {
		nsc, err := proxy.NewNetworkServicesController(kr.Client, kr.Config,
			svcInformer, epSliceInformer, podInformer, nodeInformer, &ipsetMutex)
		if err != nil {
			return fmt.Errorf("failed to create network services controller: %v", err)
		}

		_, err = svcInformer.AddEventHandler(nsc.ServiceEventHandler)
		if err != nil {
			return fmt.Errorf("failed to add ServiceEventHandler: %v", err)
		}
		_, err = epSliceInformer.AddEventHandler(nsc.EndpointSliceEventHandler)
		if err != nil {
			return fmt.Errorf("failed to add EndpointsEventHandler: %v", err)
		}

		wg.Add(1)
		go nsc.Run(healthChan, stopCh, &wg)

		// wait for the proxy firewall rules to be setup before network policies
		if kr.Config.RunFirewall {
			nsc.ProxyFirewallSetup.L.Lock()
			nsc.ProxyFirewallSetup.Wait()
			nsc.ProxyFirewallSetup.L.Unlock()
		}
	}

	if kr.Config.RunFirewall {
		iptablesCmdHandlers, ipSetHandlers, err := netpol.NewIPTablesHandlers(kr.Config)
		if err != nil {
			return fmt.Errorf("failed to create iptables handlers: %v", err)
		}
		npc, err := netpol.NewNetworkPolicyController(kr.Client,
			kr.Config, podInformer, npInformer, nsInformer, &ipsetMutex, iptablesCmdHandlers, ipSetHandlers)
		if err != nil {
			return fmt.Errorf("failed to create network policy controller: %v", err)
		}

		_, err = podInformer.AddEventHandler(npc.PodEventHandler)
		if err != nil {
			return fmt.Errorf("failed to add PodEventHandler: %v", err)
		}
		_, err = nsInformer.AddEventHandler(npc.NamespaceEventHandler)
		if err != nil {
			return fmt.Errorf("failed to add NamespaceEventHandler: %v", err)
		}
		_, err = npInformer.AddEventHandler(npc.NetworkPolicyEventHandler)
		if err != nil {
			return fmt.Errorf("failed to add NetworkPolicyEventHandler: %v", err)
		}

		wg.Add(1)
		go npc.Run(healthChan, stopCh, &wg)
	}

	if kr.Config.RunLoadBalancer {
		klog.V(0).Info("running load balancer allocator controller")
		lbc, err := lballoc.NewLoadBalancerController(kr.Client, kr.Config, svcInformer)
		if err != nil {
			return fmt.Errorf("failed to create load balancer allocator: %v", err)
		}

		_, err = svcInformer.AddEventHandler(lbc)
		if err != nil {
			return fmt.Errorf("failed to add ServiceEventHandler: %v", err)
		}

		wg.Add(1)
		go lbc.Run(healthChan, stopCh, &wg)
	}

	// Handle SIGINT and SIGTERM
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	klog.Infof("Shutting down the controllers")
	close(stopCh)

	wg.Wait()
	return nil
}

// CacheSyncOrTimeout performs cache synchronization under timeout limit
func (kr *KubeRouter) CacheSyncOrTimeout(informerFactory informers.SharedInformerFactory,
	stopCh <-chan struct{}) error {
	syncOverCh := make(chan struct{})
	go func() {
		informerFactory.WaitForCacheSync(stopCh)
		close(syncOverCh)
	}()

	select {
	case <-time.After(kr.Config.CacheSyncTimeout):
		return fmt.Errorf("%s timeout", kr.Config.CacheSyncTimeout.String())
	case <-syncOverCh:
		return nil
	}
}

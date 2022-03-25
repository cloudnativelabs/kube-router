package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/controllers/netpol"
	"github.com/cloudnativelabs/kube-router/pkg/controllers/proxy"
	"github.com/cloudnativelabs/kube-router/pkg/controllers/routing"
	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/cloudnativelabs/kube-router/pkg/version"
	"github.com/coreos/go-iptables/iptables"
	"k8s.io/klog/v2"

	v1core "k8s.io/api/core/v1"
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

	if kr.Config.MetricsPort > 0 && kr.Config.MetricsPort < 65535 {
		kr.Config.MetricsEnabled = true
		mc, err := metrics.NewMetricsController(kr.Config)
		if err != nil {
			return errors.New("Failed to create metrics controller: " + err.Error())
		}
		wg.Add(1)
		go mc.Run(healthChan, stopCh, &wg)

	} else {
		klog.Errorf("Metrics port must be over 0 and under 65535, given port: %d", kr.Config.MetricsPort)
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
			return errors.New("Failed to create network routing controller: " + err.Error())
		}

		_, err = nodeInformer.AddEventHandler(nrc.NodeEventHandler)
		if err != nil {
			return errors.New("Failed to add NodeEventHandler: " + err.Error())
		}
		_, err = svcInformer.AddEventHandler(nrc.ServiceEventHandler)
		if err != nil {
			return errors.New("Failed to add ServiceEventHandler: " + err.Error())
		}
		_, err = epInformer.AddEventHandler(nrc.EndpointsEventHandler)
		if err != nil {
			return errors.New("Failed to add EndpointsEventHandler: " + err.Error())
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
			svcInformer, epInformer, podInformer, &ipsetMutex)
		if err != nil {
			return errors.New("Failed to create network services controller: " + err.Error())
		}

		_, err = svcInformer.AddEventHandler(nsc.ServiceEventHandler)
		if err != nil {
			return errors.New("Failed to add ServiceEventHandler: " + err.Error())
		}
		_, err = epInformer.AddEventHandler(nsc.EndpointsEventHandler)
		if err != nil {
			return errors.New("Failed to add EndpointsEventHandler: " + err.Error())
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
		iptablesCmdHandlers := make(map[v1core.IPFamily]utils.IPTablesHandler, 2)
		ipSetHandlers := make(map[v1core.IPFamily]utils.IPSetHandler, 2)

		if kr.Config.EnableIPv4 {
			iptHandler, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
			if err != nil {
				return fmt.Errorf("failed to create iptables handler: %w", err)
			}
			iptablesCmdHandlers[v1core.IPv4Protocol] = iptHandler

			ipset, err := utils.NewIPSet(false)
			if err != nil {
				return fmt.Errorf("failed to create ipset handler: %w", err)
			}
			ipSetHandlers[v1core.IPv4Protocol] = ipset
		}
		if kr.Config.EnableIPv6 {
			iptHandler, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
			if err != nil {
				return fmt.Errorf("failed to create iptables handler: %w", err)
			}
			iptablesCmdHandlers[v1core.IPv6Protocol] = iptHandler

			ipset, err := utils.NewIPSet(true)
			if err != nil {
				return fmt.Errorf("failed to create ipset handler: %w", err)
			}
			ipSetHandlers[v1core.IPv6Protocol] = ipset
		}

		npc, err := netpol.NewNetworkPolicyController(kr.Client,
			kr.Config, podInformer, npInformer, nsInformer, &ipsetMutex,
			iptablesCmdHandlers, ipSetHandlers)
		if err != nil {
			return errors.New("Failed to create network policy controller: " + err.Error())
		}

		_, err = podInformer.AddEventHandler(npc.PodEventHandler)
		if err != nil {
			return errors.New("Failed to add PodEventHandler: " + err.Error())
		}
		_, err = nsInformer.AddEventHandler(npc.NamespaceEventHandler)
		if err != nil {
			return errors.New("Failed to add NamespaceEventHandler: " + err.Error())
		}
		_, err = npInformer.AddEventHandler(npc.NetworkPolicyEventHandler)
		if err != nil {
			return errors.New("Failed to add NetworkPolicyEventHandler: " + err.Error())
		}

		wg.Add(1)
		go npc.Run(healthChan, stopCh, &wg)
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
		return errors.New(kr.Config.CacheSyncTimeout.String() + " timeout")
	case <-syncOverCh:
		return nil
	}
}

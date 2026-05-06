package netpol

import (
	"bytes"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/v2/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/svcip"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"k8s.io/klog/v2"
	"sigs.k8s.io/knftables"

	v1core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	kubePodFirewallChainPrefix   = "KUBE-POD-FW-"
	kubeNetworkPolicyChainPrefix = "KUBE-NWPLCY-"
	kubeSourceIPSetPrefix        = "KUBE-SRC-"
	kubeDestinationIPSetPrefix   = "KUBE-DST-"
	kubeInputChainName           = "KUBE-ROUTER-INPUT"
	kubeForwardChainName         = "KUBE-ROUTER-FORWARD"
	kubeOutputChainName          = "KUBE-ROUTER-OUTPUT"
	kubeDefaultNetpolChain       = "KUBE-NWPLCY-DEFAULT"
	kubeCommonNetpolChain        = "KUBE-NWPLCY-COMMON"

	kubeIngressPolicyType = "ingress"
	kubeEgressPolicyType  = "egress"
	kubeBothPolicyType    = "both"

	syncVersionBase = 10
)

var (
	defaultChains = map[string]string{
		"INPUT":   kubeInputChainName,
		"FORWARD": kubeForwardChainName,
		"OUTPUT":  kubeOutputChainName,
	}
)

// NetworkPolicyController provides both ingress and egress filtering for pods as per the defined network
// policies. This interface has two implementations: one using iptables/ipsets and one using nftables.
// The implementation is selected via the UseNftablesForNetpol configuration option.
//
// Both implementations use a similar architecture with per-pod firewall chains and per-policy chains.
// Each pod requiring ingress or egress filtering gets a pod-specific chain. Each network policy has
// its own chain with rules matching source and destination pod IPs (via ipsets or nftables sets).
// Traffic is filtered by jumping from top-level chains (INPUT, FORWARD, OUTPUT) to pod-specific chains,
// then to matching network policy chains, until a match accepts the packet or it gets dropped.
type NetworkPolicyController interface {
	Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup)
	RequestFullSync()
	fullPolicySync()
	ensureTopLevelChains() error
	ensureDefaultNetworkPolicyChain()
	ensureCommonPolicyChain()

	buildNetworkPoliciesInfo() ([]networkPolicyInfo, error)
	syncNetworkPolicyChains(networkPoliciesInfo []networkPolicyInfo,
		version string) (map[string]bool, map[string]bool, error)

	PodEventHandler() cache.ResourceEventHandler
	NamespaceEventHandler() cache.ResourceEventHandler
	NetworkPolicyEventHandler() cache.ResourceEventHandler
}

// NetworkPolicyController struct to hold information required by NetworkPolicyController
type NetworkPolicyControllerBase struct {
	krNode               utils.NodeIPAndFamilyAware
	ipRanges             svcip.RangeQuerier
	serviceNodePortRange string
	filterTableRules     map[v1core.IPFamily]*bytes.Buffer

	mu                  sync.Mutex
	syncPeriod          time.Duration
	MetricsEnabled      bool
	healthChan          chan<- *healthcheck.ControllerHeartbeat
	fullSyncRequestChan chan struct{}
	ipsetMutex          *sync.Mutex

	podLister cache.Indexer
	npLister  cache.Indexer
	nsLister  cache.Indexer

	podEventHandler           cache.ResourceEventHandler
	namespaceEventHandler     cache.ResourceEventHandler
	networkPolicyEventHandler cache.ResourceEventHandler
}

func (npc *NetworkPolicyControllerBase) PodEventHandler() cache.ResourceEventHandler {
	return npc.podEventHandler
}

func (npc *NetworkPolicyControllerBase) NamespaceEventHandler() cache.ResourceEventHandler {
	return npc.namespaceEventHandler
}

func (npc *NetworkPolicyControllerBase) NetworkPolicyEventHandler() cache.ResourceEventHandler {
	return npc.networkPolicyEventHandler
}

// internal structure to represent a network policy
type networkPolicyInfo struct {
	name        string
	namespace   string
	podSelector labels.Selector

	// set of pods matching network policy spec podselector label selector
	targetPods map[string]podInfo

	// whitelist ingress rules from the network policy spec
	ingressRules []ingressRule

	// whitelist egress rules from the network policy spec
	egressRules []egressRule

	// policy type "ingress" or "egress" or "both" as defined by PolicyType in the spec
	policyType string
}

// internal structure to represent Pod
type podInfo struct {
	ip        string
	ips       []v1core.PodIP
	name      string
	namespace string
	labels    map[string]string
}

// internal structure to represent NetworkPolicyIngressRule in the spec
type ingressRule struct {
	matchAllPorts  bool
	ports          []protocolAndPort
	namedPorts     []endPoints
	matchAllSource bool
	srcPods        []podInfo
	srcIPBlocks    map[v1core.IPFamily][][]string
}

// internal structure to represent NetworkPolicyEgressRule in the spec
type egressRule struct {
	matchAllPorts        bool
	ports                []protocolAndPort
	namedPorts           []endPoints
	matchAllDestinations bool
	dstPods              []podInfo
	dstIPBlocks          map[v1core.IPFamily][][]string
}

type protocolAndPort struct {
	protocol string
	port     string
	endport  string
}

type endPoints struct {
	ips map[v1core.IPFamily][]string
	protocolAndPort
}

type numericPort2eps map[string]*endPoints
type protocol2eps map[string]numericPort2eps
type namedPort2eps map[string]protocol2eps

// RequestFullSync allows the request of a full network policy sync without blocking the callee
func (npc *NetworkPolicyControllerBase) RequestFullSync() {
	select {
	case npc.fullSyncRequestChan <- struct{}{}:
		klog.V(3).Info("Full sync request queue was empty so a full sync request was successfully sent")
	default: // Don't block if the buffered channel is full, return quickly so that we don't block callee execution
		klog.V(1).Info("Full sync request queue was full, skipping...")
	}
}

// NewNetworkPolicyController returns new NetworkPolicyController object
func NewNetworkPolicyController(clientset kubernetes.Interface,
	config *options.KubeRouterConfig, podInformer cache.SharedIndexInformer,
	npInformer cache.SharedIndexInformer, nsInformer cache.SharedIndexInformer,
	ipsetMutex *sync.Mutex, linkQ utils.LocalLinkQuerier,
	iptablesCmdHandlers map[v1core.IPFamily]utils.IPTablesHandler,
	ipSetHandlers map[v1core.IPFamily]utils.IPSetHandler,
	ipRanges svcip.RangeQuerier,
	knftInterfaces map[v1core.IPFamily]knftables.Interface,
	useNftables bool,
) (NetworkPolicyController, error) {
	npcBase := NetworkPolicyControllerBase{ipsetMutex: ipsetMutex}
	// Creating a single-item buffered channel to ensure that we only keep a single full sync request at a time,
	// additional requests would be pointless to queue since after the first one was processed the system would already
	// be up to date with all of the policy changes from any enqueued request after that
	npcBase.fullSyncRequestChan = make(chan struct{}, 1)

	var err error
	npcBase.ipRanges = ipRanges

	// Validate and parse NodePort range
	if npcBase.serviceNodePortRange, err = validateNodePortRange(config.NodePortRange); err != nil {
		return nil, err
	}

	if config.MetricsEnabled {
		// Register the metrics for this controller
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerIptablesSyncTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerIptablesV4SaveTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerIptablesV6SaveTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerIptablesV4RestoreTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerIptablesV6RestoreTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerPolicyChainsSyncTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerPolicyIpsetV4RestoreTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerPolicyIpsetV6RestoreTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerPolicyChains)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerPolicyIpsets)
		npcBase.MetricsEnabled = true
	}

	npcBase.syncPeriod = config.IPTablesSyncPeriod

	node, err := utils.GetNodeObject(clientset, config.HostnameOverride)
	if err != nil {
		return nil, err
	}

	npcBase.krNode, err = utils.NewKRNode(node, linkQ, config.EnableIPv4, config.EnableIPv6)
	if err != nil {
		return nil, err
	}
	npcBase.filterTableRules = make(map[v1core.IPFamily]*bytes.Buffer, 2)
	npcBase.podLister = podInformer.GetIndexer()
	npcBase.podEventHandler = npcBase.newPodEventHandler()

	npcBase.nsLister = nsInformer.GetIndexer()
	npcBase.namespaceEventHandler = npcBase.newNamespaceEventHandler()

	npcBase.npLister = npInformer.GetIndexer()
	npcBase.networkPolicyEventHandler = npcBase.newNetworkPolicyEventHandler()

	if useNftables {
		// Cleanup any existing iptables rules before starting nftables controller to avoid conflicts
		// in case of a restart with a different configuration
		npc := NetworkPolicyControllerIptables{NetworkPolicyControllerBase: &NetworkPolicyControllerBase{}}
		npc.Cleanup()
		return NewNetworkPolicyControllerNftables(&npcBase, clientset, config,
			podInformer, npInformer, nsInformer, linkQ, knftInterfaces)
	} else {
		// Cleanup any existing nftables rules before starting iptables controller to avoid conflicts
		// in case of a restart with a different configuration. Only attempt cleanup when nftables
		// interfaces are available so iptables-only deployments do not initialize nftables support.
		if len(knftInterfaces) > 0 {
			npc := NetworkPolicyControllerNftables{NetworkPolicyControllerBase: &NetworkPolicyControllerBase{}}
			npc.Cleanup()
		}
		return NewNetworkPolicyControllerIptables(&npcBase, clientset, config,
			podInformer, npInformer, nsInformer, linkQ, iptablesCmdHandlers, ipSetHandlers)
	}
}

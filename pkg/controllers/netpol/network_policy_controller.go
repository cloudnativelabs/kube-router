package netpol

import (
	"errors"
	"fmt"
	"k8s.io/apimachinery/pkg/util/intstr"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"

	api "k8s.io/api/core/v1"
	apiextensions "k8s.io/api/extensions/v1beta1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

// Network policy controller provides both ingress and egress filtering for the pods as per the defined network
// policies. Two different types of iptables chains are used. Each pod running on the node which either
// requires ingress or egress filtering gets a pod specific chains. Each network policy has a iptables chain, which
// has rules expressed through ipsets matching source and destination pod ip's. In the FORWARD chain of the
// filter table a rule is added to jump the traffic originating (in case of egress network policy) from the pod
// or destined (in case of ingress network policy) to the pod specific iptables chain. Each
// pod specific iptables chain has rules to jump to the network polices chains, that pod matches. So packet
// originating/destined from/to pod goes through fitler table's, FORWARD chain, followed by pod specific chain,
// followed by one or more network policy chains, till there is a match which will accept the packet, or gets
// dropped by the rule in the pod chain, if there is no match.

// NetworkPolicyController strcut to hold information required by NetworkPolicyController
type NetworkPolicyController struct {
	nodeIP          net.IP
	nodeHostName    string
	mu              sync.Mutex
	syncPeriod      time.Duration
	MetricsEnabled  bool
	v1NetworkPolicy bool
	readyForUpdates bool

	// list of all active network policies expressed as networkPolicyInfo
	networkPoliciesInfo *[]networkPolicyInfo
	ipSetHandler        *utils.IPSet

	podLister cache.Indexer
	npLister  cache.Indexer
	nsLister  cache.Indexer

	PodEventHandler           cache.ResourceEventHandler
	NamespaceEventHandler     cache.ResourceEventHandler
	NetworkPolicyEventHandler cache.ResourceEventHandler
}

// internal structure to represent a network policy
type networkPolicyInfo struct {
	name      string
	namespace string
	labels    map[string]string

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
	name      string
	namespace string
	labels    map[string]string
}

// internal stucture to represent NetworkPolicyIngressRule in the spec
type ingressRule struct {
	matchAllPorts  bool
	ports          []protocolAndPort
	matchAllSource bool
	srcPods        []podInfo
	srcIPBlocks    [][]string
}

// internal structure to represent NetworkPolicyEgressRule in the spec
type egressRule struct {
	matchAllPorts        bool
	ports                []protocolAndPort
	matchAllDestinations bool
	dstPods              []podInfo
	dstIPBlocks          [][]string
}

type protocolAndPort struct {
	protocol string
	port     string
}

func newProtocolAndPort(protocol string, port *intstr.IntOrString) protocolAndPort {
	strPort := ""

	if port != nil {
		strPort = port.String()
	}

	return protocolAndPort{protocol: protocol, port: strPort}
}

// Run runs forver till we receive notification on stopCh
func (npc *NetworkPolicyController) Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) {
	t := time.NewTicker(npc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	glog.Info("Starting network policy controller")

	// loop forever till notified to stop on stopCh
	for {
		select {
		case <-stopCh:
			glog.Info("Shutting down network policies controller")
			return
		default:
		}

		glog.V(1).Info("Performing periodic sync of iptables to reflect network policies")
		err := npc.Sync()
		if err != nil {
			glog.Errorf("Error during periodic sync of network policies in network policy controller. Error: " + err.Error())
			glog.Errorf("Skipping sending heartbeat from network policy controller as periodic sync failed.")
		} else {
			healthcheck.SendHeartBeat(healthChan, "NPC")
		}
		npc.readyForUpdates = true
		select {
		case <-stopCh:
			glog.Infof("Shutting down network policies controller")
			return
		case <-t.C:
		}
	}
}

// OnPodUpdate handles updates to pods from the Kubernetes api server
func (npc *NetworkPolicyController) OnPodUpdate(obj interface{}) {
	pod := obj.(*api.Pod)
	glog.V(2).Infof("Received update to pod: %s/%s", pod.Namespace, pod.Name)

	if !npc.readyForUpdates {
		glog.V(3).Infof("Skipping update to pod: %s/%s, controller still performing bootup full-sync", pod.Namespace, pod.Name)
		return
	}

	err := npc.Sync()
	if err != nil {
		glog.Errorf("Error syncing network policy for the update to pod: %s/%s Error: %s", pod.Namespace, pod.Name, err)
	}
}

// OnNetworkPolicyUpdate handles updates to network policy from the kubernetes api server
func (npc *NetworkPolicyController) OnNetworkPolicyUpdate(obj interface{}) {
	netpol := obj.(*networking.NetworkPolicy)
	glog.V(2).Infof("Received update for network policy: %s/%s", netpol.Namespace, netpol.Name)

	if !npc.readyForUpdates {
		glog.V(3).Infof("Skipping update to network policy: %s/%s, controller still performing bootup full-sync", netpol.Namespace, netpol.Name)
		return
	}

	err := npc.Sync()
	if err != nil {
		glog.Errorf("Error syncing network policy for the update to network policy: %s/%s Error: %s", netpol.Namespace, netpol.Name, err)
	}
}

// OnNamespaceUpdate handles updates to namespace from kubernetes api server
func (npc *NetworkPolicyController) OnNamespaceUpdate(obj interface{}) {
	namespace := obj.(*api.Namespace)
	// namespace (and annotations on it) has no significance in GA ver of network policy
	if npc.v1NetworkPolicy {
		return
	}
	glog.V(2).Infof("Received update for namespace: %s", namespace.Name)

	err := npc.Sync()
	if err != nil {
		glog.Errorf("Error syncing on namespace update: %s", err)
	}
}

// Sync synchronizes iptables to desired state of network policies
func (npc *NetworkPolicyController) Sync() error {

	var err error
	npc.mu.Lock()
	defer npc.mu.Unlock()

	start := time.Now()
	syncVersion := strconv.FormatInt(start.UnixNano(), 10)
	defer func() {
		endTime := time.Since(start)
		if npc.MetricsEnabled {
			metrics.ControllerIptablesSyncTime.Observe(endTime.Seconds())
		}
		glog.V(1).Infof("sync iptables took %v", endTime)
	}()

	glog.V(1).Infof("Starting sync of iptables with version: %s", syncVersion)
	if npc.v1NetworkPolicy {
		npc.networkPoliciesInfo, err = npc.buildNetworkPoliciesInfo()
		if err != nil {
			return errors.New("Aborting sync. Failed to build network policies: " + err.Error())
		}
	} else {
		// TODO remove the Beta support
		npc.networkPoliciesInfo, err = npc.buildBetaNetworkPoliciesInfo()
		if err != nil {
			return errors.New("Aborting sync. Failed to build network policies: " + err.Error())
		}
	}

	//TODO: Should be possible to select nftables
	return npc.SyncIPTables(syncVersion)
}


func (npc *NetworkPolicyController) getIngressNetworkPolicyEnabledPods(nodeIp string) (*map[string]podInfo, error) {
	nodePods := make(map[string]podInfo)

	for _, obj := range npc.podLister.List() {
		pod := obj.(*api.Pod)

		if strings.Compare(pod.Status.HostIP, nodeIp) != 0 {
			continue
		}
		for _, policy := range *npc.networkPoliciesInfo {
			if policy.namespace != pod.ObjectMeta.Namespace {
				continue
			}
			_, ok := policy.targetPods[pod.Status.PodIP]
			if ok && (policy.policyType == "both" || policy.policyType == "ingress") {
				glog.V(2).Infof("Found pod name: " + pod.ObjectMeta.Name + " namespace: " + pod.ObjectMeta.Namespace + " for which network policies need to be applied.")
				nodePods[pod.Status.PodIP] = podInfo{ip: pod.Status.PodIP,
					name:      pod.ObjectMeta.Name,
					namespace: pod.ObjectMeta.Namespace,
					labels:    pod.ObjectMeta.Labels}
				break
			}
		}
	}
	return &nodePods, nil

}

func (npc *NetworkPolicyController) getEgressNetworkPolicyEnabledPods(nodeIp string) (*map[string]podInfo, error) {

	nodePods := make(map[string]podInfo)

	for _, obj := range npc.podLister.List() {
		pod := obj.(*api.Pod)

		if strings.Compare(pod.Status.HostIP, nodeIp) != 0 {
			continue
		}
		for _, policy := range *npc.networkPoliciesInfo {
			if policy.namespace != pod.ObjectMeta.Namespace {
				continue
			}
			_, ok := policy.targetPods[pod.Status.PodIP]
			if ok && (policy.policyType == "both" || policy.policyType == "egress") {
				glog.V(2).Infof("Found pod name: " + pod.ObjectMeta.Name + " namespace: " + pod.ObjectMeta.Namespace + " for which network policies need to be applied.")
				nodePods[pod.Status.PodIP] = podInfo{ip: pod.Status.PodIP,
					name:      pod.ObjectMeta.Name,
					namespace: pod.ObjectMeta.Namespace,
					labels:    pod.ObjectMeta.Labels}
				break
			}
		}
	}
	return &nodePods, nil
}

func (npc *NetworkPolicyController) checkForNamedPorts(ports *[]networking.NetworkPolicyPort) error {
	for _, npProtocolPort := range *ports {
		if npProtocolPort.Port != nil && npProtocolPort.Port.Type == intstr.String {
			return fmt.Errorf("named port %s in network policy", npProtocolPort.Port.String())
		}
	}
	return nil
}

func (npc *NetworkPolicyController) buildNetworkPoliciesInfo() (*[]networkPolicyInfo, error) {

	NetworkPolicies := make([]networkPolicyInfo, 0)

	for _, policyObj := range npc.npLister.List() {

		policy, ok := policyObj.(*networking.NetworkPolicy)
		if !ok {
			return nil, fmt.Errorf("Failed to convert")
		}
		newPolicy := networkPolicyInfo{
			name:       policy.Name,
			namespace:  policy.Namespace,
			labels:     policy.Spec.PodSelector.MatchLabels,
			policyType: "ingress",
		}

		// check if there is explicitly specified PolicyTypes in the spec
		if len(policy.Spec.PolicyTypes) > 0 {
			ingressType, egressType := false, false
			for _, policyType := range policy.Spec.PolicyTypes {
				if policyType == networking.PolicyTypeIngress {
					ingressType = true
				}
				if policyType == networking.PolicyTypeEgress {
					egressType = true
				}
			}
			if ingressType && egressType {
				newPolicy.policyType = "both"
			} else if egressType {
				newPolicy.policyType = "egress"
			} else if ingressType {
				newPolicy.policyType = "ingress"
			}
		} else {
			if policy.Spec.Egress != nil && policy.Spec.Ingress != nil {
				newPolicy.policyType = "both"
			} else if policy.Spec.Egress != nil {
				newPolicy.policyType = "egress"
			} else if policy.Spec.Ingress != nil {
				newPolicy.policyType = "ingress"
			}
		}

		matchingPods, err := npc.ListPodsByNamespaceAndLabels(policy.Namespace, policy.Spec.PodSelector.MatchLabels)
		newPolicy.targetPods = make(map[string]podInfo)
		if err == nil {
			for _, matchingPod := range matchingPods {
				if matchingPod.Status.PodIP == "" {
					continue
				}
				newPolicy.targetPods[matchingPod.Status.PodIP] = podInfo{ip: matchingPod.Status.PodIP,
					name:      matchingPod.ObjectMeta.Name,
					namespace: matchingPod.ObjectMeta.Namespace,
					labels:    matchingPod.ObjectMeta.Labels}
			}
		}

		if policy.Spec.Ingress == nil {
			newPolicy.ingressRules = nil
		} else {
			newPolicy.ingressRules = make([]ingressRule, 0)
		}

		if policy.Spec.Egress == nil {
			newPolicy.egressRules = nil
		} else {
			newPolicy.egressRules = make([]egressRule, 0)
		}

		var skipPolicy bool
		for _, specIngressRule := range policy.Spec.Ingress {
			ingressRule := ingressRule{}

			ingressRule.ports = make([]protocolAndPort, 0)

			// If this field is empty or missing in the spec, this rule matches all ports
			if len(specIngressRule.Ports) == 0 {
				ingressRule.matchAllPorts = true
			} else {
				ingressRule.matchAllPorts = false
				if npc.checkForNamedPorts(&specIngressRule.Ports) != nil {
					glog.Errorf("Found a network policy: %s/%s with named port. Skipping processing network policy as its unspported yet.", policy.Namespace, policy.Name)
					skipPolicy = true
					continue
				}
				for _, port := range specIngressRule.Ports {
					protocolAndPort := newProtocolAndPort(string(*port.Protocol), port.Port)
					ingressRule.ports = append(ingressRule.ports, protocolAndPort)
				}
			}

			ingressRule.srcPods = make([]podInfo, 0)
			ingressRule.srcIPBlocks = make([][]string, 0)

			// If this field is empty or missing in the spec, this rule matches all sources
			if len(specIngressRule.From) == 0 {
				ingressRule.matchAllSource = true
			} else {
				ingressRule.matchAllSource = false
				for _, peer := range specIngressRule.From {
					if peerPods, err := npc.evalPodPeer(policy, peer); err == nil {
						for _, peerPod := range peerPods {
							if peerPod.Status.PodIP == "" {
								continue
							}
							ingressRule.srcPods = append(ingressRule.srcPods,
								podInfo{ip: peerPod.Status.PodIP,
									name:      peerPod.ObjectMeta.Name,
									namespace: peerPod.ObjectMeta.Namespace,
									labels:    peerPod.ObjectMeta.Labels})
						}
					}
					ingressRule.srcIPBlocks = append(ingressRule.srcIPBlocks, npc.evalIPBlockPeer(peer)...)
				}
			}

			newPolicy.ingressRules = append(newPolicy.ingressRules, ingressRule)
		}

		for _, specEgressRule := range policy.Spec.Egress {
			egressRule := egressRule{}

			egressRule.ports = make([]protocolAndPort, 0)

			// If this field is empty or missing in the spec, this rule matches all ports
			if len(specEgressRule.Ports) == 0 {
				egressRule.matchAllPorts = true
			} else {
				egressRule.matchAllPorts = false
				if npc.checkForNamedPorts(&specEgressRule.Ports) != nil {
					glog.Errorf("Found a network policy: %s/%s with named port. Skipping processing network policy as its unspported yet.", policy.Namespace, policy.Name)
					skipPolicy = true
					continue
				}
				for _, port := range specEgressRule.Ports {
					protocolAndPort := newProtocolAndPort(string(*port.Protocol), port.Port)
					egressRule.ports = append(egressRule.ports, protocolAndPort)
				}
			}

			egressRule.dstPods = make([]podInfo, 0)
			egressRule.dstIPBlocks = make([][]string, 0)

			// If this field is empty or missing in the spec, this rule matches all sources
			if len(specEgressRule.To) == 0 {
				egressRule.matchAllDestinations = true
			} else {
				egressRule.matchAllDestinations = false
				for _, peer := range specEgressRule.To {
					if peerPods, err := npc.evalPodPeer(policy, peer); err == nil {
						for _, peerPod := range peerPods {
							if peerPod.Status.PodIP == "" {
								continue
							}
							egressRule.dstPods = append(egressRule.dstPods,
								podInfo{ip: peerPod.Status.PodIP,
									name:      peerPod.ObjectMeta.Name,
									namespace: peerPod.ObjectMeta.Namespace,
									labels:    peerPod.ObjectMeta.Labels})
						}
					}
					egressRule.dstIPBlocks = append(egressRule.dstIPBlocks, npc.evalIPBlockPeer(peer)...)
				}
			}

			newPolicy.egressRules = append(newPolicy.egressRules, egressRule)
		}
		if !skipPolicy {
			NetworkPolicies = append(NetworkPolicies, newPolicy)
		}
	}

	return &NetworkPolicies, nil
}

func (npc *NetworkPolicyController) evalPodPeer(policy *networking.NetworkPolicy, peer networking.NetworkPolicyPeer) ([]*api.Pod, error) {

	var matchingPods []*api.Pod
	matchingPods = make([]*api.Pod, 0)
	var err error
	// spec can have both PodSelector AND NamespaceSelector
	if peer.NamespaceSelector != nil {
		namespaces, err := npc.ListNamespaceByLabels(peer.NamespaceSelector.MatchLabels)
		if err != nil {
			return nil, errors.New("Failed to build network policies info due to " + err.Error())
		}

		var podSelectorLabels map[string]string
		if peer.PodSelector != nil {
			podSelectorLabels = peer.PodSelector.MatchLabels
		}
		for _, namespace := range namespaces {
			namespacePods, err := npc.ListPodsByNamespaceAndLabels(namespace.Name, podSelectorLabels)
			if err != nil {
				return nil, errors.New("Failed to build network policies info due to " + err.Error())
			}
			matchingPods = append(matchingPods, namespacePods...)
		}
	} else if peer.PodSelector != nil {
		matchingPods, err = npc.ListPodsByNamespaceAndLabels(policy.Namespace, peer.PodSelector.MatchLabels)
	}

	return matchingPods, err
}

func (npc *NetworkPolicyController) ListPodsByNamespaceAndLabels(namespace string, labelsToMatch labels.Set) (ret []*api.Pod, err error) {
	podLister := listers.NewPodLister(npc.podLister)
	allMatchedNameSpacePods, err := podLister.Pods(namespace).List(labelsToMatch.AsSelector())
	if err != nil {
		return nil, err
	}
	return allMatchedNameSpacePods, nil
}

func (npc *NetworkPolicyController) ListNamespaceByLabels(set labels.Set) ([]*api.Namespace, error) {
	namespaceLister := listers.NewNamespaceLister(npc.nsLister)
	matchedNamespaces, err := namespaceLister.List(set.AsSelector())
	if err != nil {
		return nil, err
	}
	return matchedNamespaces, nil
}

func (npc *NetworkPolicyController) evalIPBlockPeer(peer networking.NetworkPolicyPeer) [][]string {
	ipBlock := make([][]string, 0)
	if peer.PodSelector == nil && peer.NamespaceSelector == nil && peer.IPBlock != nil {
		if cidr := peer.IPBlock.CIDR; strings.HasSuffix(cidr, "/0") {
			ipBlock = append(ipBlock, []string{"0.0.0.0/1", utils.OptionTimeout, "0"}, []string{"128.0.0.0/1", utils.OptionTimeout, "0"})
		} else {
			ipBlock = append(ipBlock, []string{cidr, utils.OptionTimeout, "0"})
		}
		for _, except := range peer.IPBlock.Except {
			if strings.HasSuffix(except, "/0") {
				ipBlock = append(ipBlock, []string{"0.0.0.0/1", utils.OptionTimeout, "0", utils.OptionNoMatch}, []string{"128.0.0.0/1", utils.OptionTimeout, "0", utils.OptionNoMatch})
			} else {
				ipBlock = append(ipBlock, []string{except, utils.OptionTimeout, "0", utils.OptionNoMatch})
			}
		}
	}
	return ipBlock
}

func (npc *NetworkPolicyController) buildBetaNetworkPoliciesInfo() (*[]networkPolicyInfo, error) {

	NetworkPolicies := make([]networkPolicyInfo, 0)

	for _, policyObj := range npc.npLister.List() {

		policy, _ := policyObj.(*apiextensions.NetworkPolicy)
		newPolicy := networkPolicyInfo{
			name:      policy.Name,
			namespace: policy.Namespace,
			labels:    policy.Spec.PodSelector.MatchLabels,
		}
		matchingPods, err := npc.ListPodsByNamespaceAndLabels(policy.Namespace, policy.Spec.PodSelector.MatchLabels)
		newPolicy.targetPods = make(map[string]podInfo)
		newPolicy.ingressRules = make([]ingressRule, 0)
		if err == nil {
			for _, matchingPod := range matchingPods {
				if matchingPod.Status.PodIP == "" {
					continue
				}
				newPolicy.targetPods[matchingPod.Status.PodIP] = podInfo{ip: matchingPod.Status.PodIP,
					name:      matchingPod.ObjectMeta.Name,
					namespace: matchingPod.ObjectMeta.Namespace,
					labels:    matchingPod.ObjectMeta.Labels}
			}
		}

		for _, specIngressRule := range policy.Spec.Ingress {
			ingressRule := ingressRule{}

			ingressRule.ports = make([]protocolAndPort, 0)
			for _, port := range specIngressRule.Ports {
				protocolAndPort := newProtocolAndPort(string(*port.Protocol), port.Port)
				ingressRule.ports = append(ingressRule.ports, protocolAndPort)
			}

			ingressRule.srcPods = make([]podInfo, 0)
			for _, peer := range specIngressRule.From {
				matchingPods, err := npc.ListPodsByNamespaceAndLabels(policy.Namespace, peer.PodSelector.MatchLabels)
				if err == nil {
					for _, matchingPod := range matchingPods {
						if matchingPod.Status.PodIP == "" {
							continue
						}
						ingressRule.srcPods = append(ingressRule.srcPods,
							podInfo{ip: matchingPod.Status.PodIP,
								name:      matchingPod.ObjectMeta.Name,
								namespace: matchingPod.ObjectMeta.Namespace,
								labels:    matchingPod.ObjectMeta.Labels})
					}
				}
			}
			newPolicy.ingressRules = append(newPolicy.ingressRules, ingressRule)
		}
		NetworkPolicies = append(NetworkPolicies, newPolicy)
	}

	return &NetworkPolicies, nil
}

func (npc *NetworkPolicyController) newPodEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			npc.OnPodUpdate(obj)

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newPoObj := newObj.(*api.Pod)
			oldPoObj := oldObj.(*api.Pod)
			if newPoObj.Status.Phase != oldPoObj.Status.Phase || newPoObj.Status.PodIP != oldPoObj.Status.PodIP {
				// for the network policies, we are only interested in pod status phase change or IP change
				npc.OnPodUpdate(newObj)
			}
		},
		DeleteFunc: func(obj interface{}) {
			npc.OnPodUpdate(obj)
		},
	}
}

func (npc *NetworkPolicyController) newNamespaceEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			npc.OnNamespaceUpdate(obj)

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			npc.OnNamespaceUpdate(newObj)

		},
		DeleteFunc: func(obj interface{}) {
			npc.OnNamespaceUpdate(obj)

		},
	}
}

func (npc *NetworkPolicyController) newNetworkPolicyEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			npc.OnNetworkPolicyUpdate(obj)

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			npc.OnNetworkPolicyUpdate(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			npc.OnNetworkPolicyUpdate(obj)

		},
	}
}

// NewNetworkPolicyController returns new NetworkPolicyController object
func NewNetworkPolicyController(clientset kubernetes.Interface,
	config *options.KubeRouterConfig, podInformer cache.SharedIndexInformer,
	npInformer cache.SharedIndexInformer, nsInformer cache.SharedIndexInformer) (*NetworkPolicyController, error) {
	npc := NetworkPolicyController{}

	if config.MetricsEnabled {
		//Register the metrics for this controller
		prometheus.MustRegister(metrics.ControllerIptablesSyncTime)
		prometheus.MustRegister(metrics.ControllerPolicyChainsSyncTime)
		npc.MetricsEnabled = true
	}

	npc.syncPeriod = config.IPTablesSyncPeriod

	npc.v1NetworkPolicy = true
	v, _ := clientset.Discovery().ServerVersion()
	valid := regexp.MustCompile("[0-9]")
	v.Minor = strings.Join(valid.FindAllString(v.Minor, -1), "")
	minorVer, _ := strconv.Atoi(v.Minor)
	if v.Major == "1" && minorVer < 7 {
		npc.v1NetworkPolicy = false
	}

	node, err := utils.GetNodeObject(clientset, config.HostnameOverride)
	if err != nil {
		return nil, err
	}

	npc.nodeHostName = node.Name

	nodeIP, err := utils.GetNodeIP(node)
	if err != nil {
		return nil, err
	}
	npc.nodeIP = nodeIP

	ipset, err := utils.NewIPSet(false)
	if err != nil {
		return nil, err
	}
	err = ipset.Save()
	if err != nil {
		return nil, err
	}
	npc.ipSetHandler = ipset

	npc.podLister = podInformer.GetIndexer()
	npc.PodEventHandler = npc.newPodEventHandler()

	npc.nsLister = nsInformer.GetIndexer()
	npc.NamespaceEventHandler = npc.newNamespaceEventHandler()

	npc.npLister = npInformer.GetIndexer()
	npc.NetworkPolicyEventHandler = npc.newNetworkPolicyEventHandler()

	return &npc, nil
}

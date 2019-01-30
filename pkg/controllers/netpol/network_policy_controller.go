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

	// list of all active network policies expressed as NetworkPolicyInfo
	networkPoliciesInfo *[]NetworkPolicyInfo
	handler             PolicyHandler

	podLister cache.Indexer
	npLister  cache.Indexer
	nsLister  cache.Indexer

	PodEventHandler           cache.ResourceEventHandler
	NamespaceEventHandler     cache.ResourceEventHandler
	NetworkPolicyEventHandler cache.ResourceEventHandler
}

// internal structure to represent a network policy
type NetworkPolicyInfo struct {
	Name      string
	Namespace string
	labels    map[string]string

	// set of pods matching network policy spec podselector label selector
	TargetPods map[string]PodInfo

	// whitelist ingress rules from the network policy spec
	IngressRules []IngressRule

	// whitelist egress rules from the network policy spec
	EgressRules []EgressRule

	// policy type "ingress" or "egress" or "both" as defined by PolicyType in the spec
	policyType string
}

// internal structure to represent Pod
type PodInfo struct {
	IP        string
	Name      string
	Namespace string
	Labels    map[string]string
	Policies  []NetworkPolicyInfo
}

// internal stucture to represent NetworkPolicyIngressRule in the spec
type IngressRule struct {
	MatchAllPorts  bool
	Ports          []ProtocolAndPort
	MatchAllSource bool
	SrcPods        []PodInfo
	SrcIPBlocks    []*networking.IPBlock
}

// internal structure to represent NetworkPolicyEgressRule in the spec
type EgressRule struct {
	MatchAllPorts        bool
	Ports                []ProtocolAndPort
	MatchAllDestinations bool
	DstPods              []PodInfo
	DstIPBlocks          []*networking.IPBlock
}

type ProtocolAndPort struct {
	Protocol string
	Port     string
}

type PolicyHandler interface {
	Sync(networkPoliciesInfo *[]NetworkPolicyInfo, ingressPods, egressPods *map[string]PodInfo) error
	Cleanup()
	Shutdown()
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
			npc.handler.Shutdown()
			return
		default:
		}

		glog.V(1).Info("Performing periodic sync to reflect network policies")
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
	defer func() {
		endTime := time.Since(start)
		if npc.MetricsEnabled {
			metrics.ControllerIptablesSyncTime.Observe(endTime.Seconds())
		}
		glog.V(1).Infof("sync network policies took %v", endTime)
	}()

	glog.V(1).Infof("Starting sync of network policies")
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

	ingressPods, err := npc.getIngressNetworkPolicyEnabledPods(npc.nodeIP.String())
	if err != nil {
		return errors.New("Aborting sync. Failed to get ingress pods: " + err.Error())
	}
	egressPods, err := npc.getEgressNetworkPolicyEnabledPods(npc.nodeIP.String())
	if err != nil {
		return errors.New("Aborting sync. Failed to build egress pods: " + err.Error())
	}

	// delegate actual sync to the handler
	return npc.handler.Sync(npc.networkPoliciesInfo, ingressPods, egressPods)
}

func (npc *NetworkPolicyController) Cleanup() {
	// delegate cleanup to the handler
	npc.handler.Cleanup()
}

func (policy NetworkPolicyInfo) Matches(pod PodInfo) bool {
	_, ok := policy.TargetPods[pod.IP]
	return ok
}

func (npc *NetworkPolicyController) getIngressNetworkPolicyEnabledPods(nodeIp string) (*map[string]PodInfo, error) {
	nodePods := make(map[string]PodInfo)

	for _, obj := range npc.podLister.List() {
		pod := obj.(*api.Pod)

		if strings.Compare(pod.Status.HostIP, nodeIp) != 0 {
			continue
		}
		podInfo := PodInfo{IP: pod.Status.PodIP,
			Name:      pod.ObjectMeta.Name,
			Namespace: pod.ObjectMeta.Namespace,
			Labels:    pod.ObjectMeta.Labels}

		for _, policy := range *npc.networkPoliciesInfo {
			if policy.Namespace != pod.ObjectMeta.Namespace {
				continue
			}
			_, ok := policy.TargetPods[pod.Status.PodIP]
			if ok && (policy.policyType == "both" || policy.policyType == "ingress") {
				glog.V(2).Infof("Found pod name: " + pod.ObjectMeta.Name + " namespace: " + pod.ObjectMeta.Namespace + " for which network policies need to be applied.")
				podInfo.Policies = append(podInfo.Policies, policy)
				nodePods[pod.Status.PodIP] = podInfo
				break
			}
		}
	}
	return &nodePods, nil

}

func (npc *NetworkPolicyController) getEgressNetworkPolicyEnabledPods(nodeIp string) (*map[string]PodInfo, error) {

	nodePods := make(map[string]PodInfo)

	for _, obj := range npc.podLister.List() {
		pod := obj.(*api.Pod)

		if strings.Compare(pod.Status.HostIP, nodeIp) != 0 {
			continue
		}
		podInfo := PodInfo{IP: pod.Status.PodIP,
			Name:      pod.ObjectMeta.Name,
			Namespace: pod.ObjectMeta.Namespace,
			Labels:    pod.ObjectMeta.Labels}

		for _, policy := range *npc.networkPoliciesInfo {
			if policy.Namespace != pod.ObjectMeta.Namespace {
				continue
			}
			_, ok := policy.TargetPods[pod.Status.PodIP]
			if ok && (policy.policyType == "both" || policy.policyType == "egress") {
				glog.V(2).Infof("Found pod name: " + pod.ObjectMeta.Name + " namespace: " + pod.ObjectMeta.Namespace + " for which network policies need to be applied.")
				podInfo.Policies = append(podInfo.Policies, policy)
				nodePods[pod.Status.PodIP] = podInfo
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

func (npc *NetworkPolicyController) buildNetworkPoliciesInfo() (*[]NetworkPolicyInfo, error) {

	NetworkPolicies := make([]NetworkPolicyInfo, 0)

	for _, policyObj := range npc.npLister.List() {

		policy, ok := policyObj.(*networking.NetworkPolicy)
		if !ok {
			return nil, fmt.Errorf("Failed to convert")
		}
		newPolicy := NetworkPolicyInfo{
			Name:       policy.Name,
			Namespace:  policy.Namespace,
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
		newPolicy.TargetPods = make(map[string]PodInfo)
		if err == nil {
			for _, matchingPod := range matchingPods {
				if matchingPod.Status.PodIP == "" {
					continue
				}
				newPolicy.TargetPods[matchingPod.Status.PodIP] = PodInfo{IP: matchingPod.Status.PodIP,
					Name:      matchingPod.ObjectMeta.Name,
					Namespace: matchingPod.ObjectMeta.Namespace,
					Labels:    matchingPod.ObjectMeta.Labels}
			}
		}

		if policy.Spec.Ingress == nil {
			newPolicy.IngressRules = nil
		} else {
			newPolicy.IngressRules = make([]IngressRule, 0)
		}

		if policy.Spec.Egress == nil {
			newPolicy.EgressRules = nil
		} else {
			newPolicy.EgressRules = make([]EgressRule, 0)
		}

		var skipPolicy bool
		for _, specIngressRule := range policy.Spec.Ingress {
			ingressRule := IngressRule{}

			ingressRule.Ports = make([]ProtocolAndPort, 0)

			// If this field is empty or missing in the spec, this rule matches all Ports
			if len(specIngressRule.Ports) == 0 {
				ingressRule.MatchAllPorts = true
			} else {
				ingressRule.MatchAllPorts = false
				if npc.checkForNamedPorts(&specIngressRule.Ports) != nil {
					glog.Errorf("Found a network policy: %s/%s with named port. Skipping processing network policy as its unspported yet.", policy.Namespace, policy.Name)
					skipPolicy = true
					continue
				}
				for _, port := range specIngressRule.Ports {
					protocolAndPort := NewProtocolAndPort(string(*port.Protocol), port.Port)
					ingressRule.Ports = append(ingressRule.Ports, protocolAndPort)
				}
			}

			ingressRule.SrcPods = make([]PodInfo, 0)
			ingressRule.SrcIPBlocks = make([]*networking.IPBlock, 0)

			// If this field is empty or missing in the spec, this rule matches all sources
			if len(specIngressRule.From) == 0 {
				ingressRule.MatchAllSource = true
			} else {
				ingressRule.MatchAllSource = false
				for _, peer := range specIngressRule.From {
					peerPods, err := npc.evalPodPeer(policy, peer)
					matchingPods = append(matchingPods, peerPods...)
					ingressRule.SrcIPBlocks = append(ingressRule.SrcIPBlocks, npc.evalIPBlockPeer(peer))
					if err == nil {
						for _, peerPod := range peerPods {
							if peerPod.Status.PodIP == "" {
								continue
							}
							ingressRule.SrcPods = append(ingressRule.SrcPods,
								PodInfo{IP: peerPod.Status.PodIP,
									Name:      peerPod.ObjectMeta.Name,
									Namespace: peerPod.ObjectMeta.Namespace,
									Labels:    peerPod.ObjectMeta.Labels})
						}
					}
				}
			}

			newPolicy.IngressRules = append(newPolicy.IngressRules, ingressRule)
		}

		for _, specEgressRule := range policy.Spec.Egress {
			egressRule := EgressRule{}

			egressRule.Ports = make([]ProtocolAndPort, 0)

			// If this field is empty or missing in the spec, this rule matches all Ports
			if len(specEgressRule.Ports) == 0 {
				egressRule.MatchAllPorts = true
			} else {
				egressRule.MatchAllPorts = false
				if npc.checkForNamedPorts(&specEgressRule.Ports) != nil {
					glog.Errorf("Found a network policy: %s/%s with named port. Skipping processing network policy as its unspported yet.", policy.Namespace, policy.Name)
					skipPolicy = true
					continue
				}
				for _, port := range specEgressRule.Ports {
					protocolAndPort := NewProtocolAndPort(string(*port.Protocol), port.Port)
					egressRule.Ports = append(egressRule.Ports, protocolAndPort)
				}
			}

			egressRule.DstPods = make([]PodInfo, 0)
			egressRule.DstIPBlocks = make([]*networking.IPBlock, 0)

			// If this field is empty or missing in the spec, this rule matches all sources
			if len(specEgressRule.To) == 0 {
				egressRule.MatchAllDestinations = true
			} else {
				egressRule.MatchAllDestinations = false
				for _, peer := range specEgressRule.To {
					peerPods, err := npc.evalPodPeer(policy, peer)
					matchingPods = append(matchingPods, peerPods...)
					egressRule.DstIPBlocks = append(egressRule.DstIPBlocks, npc.evalIPBlockPeer(peer))
					if err == nil {
						for _, peerPod := range peerPods {
							if peerPod.Status.PodIP == "" {
								continue
							}
							egressRule.DstPods = append(egressRule.DstPods,
								PodInfo{IP: peerPod.Status.PodIP,
									Name:      peerPod.ObjectMeta.Name,
									Namespace: peerPod.ObjectMeta.Namespace,
									Labels:    peerPod.ObjectMeta.Labels})
						}
					}
				}
			}

			newPolicy.EgressRules = append(newPolicy.EgressRules, egressRule)
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

func (npc *NetworkPolicyController) evalIPBlockPeer(peer networking.NetworkPolicyPeer) *networking.IPBlock {
	if peer.PodSelector == nil && peer.NamespaceSelector == nil && peer.IPBlock != nil {
		return peer.IPBlock
	}
	return nil
}

func (npc *NetworkPolicyController) buildBetaNetworkPoliciesInfo() (*[]NetworkPolicyInfo, error) {

	NetworkPolicies := make([]NetworkPolicyInfo, 0)

	for _, policyObj := range npc.npLister.List() {

		policy, _ := policyObj.(*apiextensions.NetworkPolicy)
		newPolicy := NetworkPolicyInfo{
			Name:      policy.Name,
			Namespace: policy.Namespace,
			labels:    policy.Spec.PodSelector.MatchLabels,
		}
		matchingPods, err := npc.ListPodsByNamespaceAndLabels(policy.Namespace, policy.Spec.PodSelector.MatchLabels)
		newPolicy.TargetPods = make(map[string]PodInfo)
		newPolicy.IngressRules = make([]IngressRule, 0)
		if err == nil {
			for _, matchingPod := range matchingPods {
				if matchingPod.Status.PodIP == "" {
					continue
				}
				newPolicy.TargetPods[matchingPod.Status.PodIP] = PodInfo{IP: matchingPod.Status.PodIP,
					Name:      matchingPod.ObjectMeta.Name,
					Namespace: matchingPod.ObjectMeta.Namespace,
					Labels:    matchingPod.ObjectMeta.Labels}
			}
		}

		for _, specIngressRule := range policy.Spec.Ingress {
			ingressRule := IngressRule{}

			ingressRule.Ports = make([]ProtocolAndPort, 0)
			for _, port := range specIngressRule.Ports {
				protocolAndPort := NewProtocolAndPort(string(*port.Protocol), port.Port)
				ingressRule.Ports = append(ingressRule.Ports, protocolAndPort)
			}

			ingressRule.SrcPods = make([]PodInfo, 0)
			for _, peer := range specIngressRule.From {
				matchingPods, err := npc.ListPodsByNamespaceAndLabels(policy.Namespace, peer.PodSelector.MatchLabels)
				if err == nil {
					for _, matchingPod := range matchingPods {
						if matchingPod.Status.PodIP == "" {
							continue
						}
						ingressRule.SrcPods = append(ingressRule.SrcPods,
							PodInfo{IP: matchingPod.Status.PodIP,
								Name:      matchingPod.ObjectMeta.Name,
								Namespace: matchingPod.ObjectMeta.Namespace,
								Labels:    matchingPod.ObjectMeta.Labels})
					}
				}
			}
			newPolicy.IngressRules = append(newPolicy.IngressRules, ingressRule)
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

	npc.podLister = podInformer.GetIndexer()
	npc.PodEventHandler = npc.newPodEventHandler()

	npc.nsLister = nsInformer.GetIndexer()
	npc.NamespaceEventHandler = npc.newNamespaceEventHandler()

	npc.npLister = npInformer.GetIndexer()
	npc.NetworkPolicyEventHandler = npc.newNetworkPolicyEventHandler()

	if config.NetworkPolicyHandler == "nftables" {
		npc.handler, err = NewNFTablesHandler()
		if err != nil {
			return nil, err
		}
	} else {
		npc.handler, err = NewIPTablesHandler()
		if err != nil {
			return nil, err
		}
	}

	return &npc, nil
}

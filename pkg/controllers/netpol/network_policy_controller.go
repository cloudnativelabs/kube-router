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
	healthChan      chan<- *healthcheck.ControllerHeartbeat

	// list of all active network policies expressed as NetworkPolicyInfo
	networkPoliciesInfo *[]NetworkPolicyInfo
	handler             PolicyHandler

	podLister     cache.Indexer
	serviceLister cache.Indexer
	npLister      cache.Indexer
	nsLister      cache.Indexer

	PodEventHandler           cache.ResourceEventHandler
	ServiceEventHandler       cache.ResourceEventHandler
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
	NamedPorts     []EndPoints
	MatchAllSource bool
	SrcPods        []PodInfo
	SrcIPBlocks    []*networking.IPBlock
}

// internal structure to represent NetworkPolicyEgressRule in the spec
type EgressRule struct {
	MatchAllPorts        bool
	Ports                []ProtocolAndPort
	NamedPorts           []EndPoints
	MatchAllDestinations bool
	DstPods              []PodInfo
	DstIPBlocks          []*networking.IPBlock
}

type ProtocolAndPort struct {
	Protocol string
	Port     string
}

type EndPoints struct {
	ips []string
	ProtocolAndPort
}

type NumericPortToEndpoints map[string]*EndPoints
type ProtocolToEndpoints map[string]NumericPortToEndpoints
type NamedPortToEndpoints map[string]ProtocolToEndpoints

type PolicyHandler interface {
	Init()
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
	npc.healthChan = healthChan

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

// OnServiceUpdate handles updates to services from kubernetes api server
func (npc *NetworkPolicyController) OnServiceUpdate(obj interface{}) {
	service := obj.(*api.Service)
	glog.V(2).Infof("Received update for service: %s", service.Name)

	if !npc.readyForUpdates {
		glog.V(3).Infof("Skipping update to service: %s/%s, controller still performing bootup full-sync", service.Namespace, service.Name)
		return
	}

	err := npc.Sync()
	if err != nil {
		glog.Errorf("Error syncing on service update: %s", err)
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

	healthcheck.SendHeartBeat(npc.healthChan, "NPC")
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

func (npc *NetworkPolicyController) processNetworkPolicyPorts(npPorts []networking.NetworkPolicyPort, namedPortToEndpoints NamedPortToEndpoints) (numericPorts []ProtocolAndPort, namedPorts []EndPoints) {
	numericPorts, namedPorts = make([]ProtocolAndPort, 0), make([]EndPoints, 0)
	for _, npPort := range npPorts {
		if npPort.Port == nil {
			numericPorts = append(numericPorts, ProtocolAndPort{Port: "", Protocol: string(*npPort.Protocol)})
		} else if npPort.Port.Type == intstr.Int {
			numericPorts = append(numericPorts, ProtocolAndPort{Port: npPort.Port.String(), Protocol: string(*npPort.Protocol)})
		} else {
			if protocolToEndpoints, ok := namedPortToEndpoints[npPort.Port.String()]; ok {
				if numericPortToEndpoints, ok := protocolToEndpoints[string(*npPort.Protocol)]; ok {
					for _, eps := range numericPortToEndpoints {
						namedPorts = append(namedPorts, *eps)
					}
				}
			}
		}
	}
	return
}

func (npc *NetworkPolicyController) processBetaNetworkPolicyPorts(npPorts []apiextensions.NetworkPolicyPort, namedPortToEndpoints NamedPortToEndpoints) (numericPorts []ProtocolAndPort, namedPorts []EndPoints) {
	numericPorts, namedPorts = make([]ProtocolAndPort, 0), make([]EndPoints, 0)
	for _, npPort := range npPorts {
		if npPort.Port == nil {
			numericPorts = append(numericPorts, ProtocolAndPort{Port: "", Protocol: string(*npPort.Protocol)})
		} else if npPort.Port.Type == intstr.Int {
			numericPorts = append(numericPorts, ProtocolAndPort{Port: npPort.Port.String(), Protocol: string(*npPort.Protocol)})
		} else {
			if protocolToEndpoints, ok := namedPortToEndpoints[npPort.Port.String()]; ok {
				if numericPortToEndpoints, ok := protocolToEndpoints[string(*npPort.Protocol)]; ok {
					for _, eps := range numericPortToEndpoints {
						namedPorts = append(namedPorts, *eps)
					}
				}
			}
		}
	}
	return
}

func (npc *NetworkPolicyController) buildNetworkPoliciesInfo() (*[]NetworkPolicyInfo, error) {

	NetworkPolicies := make([]NetworkPolicyInfo, 0)

	for _, policyObj := range npc.npLister.List() {

		policy, ok := policyObj.(*networking.NetworkPolicy)
		if !ok {
			return nil, fmt.Errorf("failed to convert")
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
		namedPortToEndpoints := make(NamedPortToEndpoints)
		if err == nil {
			for _, matchingPod := range matchingPods {
				if matchingPod.Status.PodIP == "" {
					continue
				}
				newPolicy.TargetPods[matchingPod.Status.PodIP] = PodInfo{IP: matchingPod.Status.PodIP,
					Name:      matchingPod.ObjectMeta.Name,
					Namespace: matchingPod.ObjectMeta.Namespace,
					Labels:    matchingPod.ObjectMeta.Labels}
				npc.grabNamedPortFromPod(matchingPod, &namedPortToEndpoints)
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

		for _, specIngressRule := range policy.Spec.Ingress {
			ingressRule := IngressRule{}
			ingressRule.SrcPods = make([]PodInfo, 0)
			ingressRule.SrcIPBlocks = make([]*networking.IPBlock, 0)

			// If this field is empty or missing in the spec, this rule matches all sources
			if len(specIngressRule.From) == 0 {
				ingressRule.MatchAllSource = true
			} else {
				ingressRule.MatchAllSource = false
				for _, peer := range specIngressRule.From {
					if ipBlockPeer := npc.evalIPBlockPeer(peer); ipBlockPeer != nil {
						ingressRule.SrcIPBlocks = append(ingressRule.SrcIPBlocks, ipBlockPeer)
					}
					peerPods, err := npc.evalPodPeer(policy, peer)
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
					} else {
						glog.Errorf("Error evaluating pod peers for ingress rule: %s", err.Error())
					}
				}
			}

			ingressRule.Ports = make([]ProtocolAndPort, 0)
			ingressRule.NamedPorts = make([]EndPoints, 0)
			// If this field is empty or missing in the spec, this rule matches all Ports
			if len(specIngressRule.Ports) == 0 {
				ingressRule.MatchAllPorts = true
			} else {
				ingressRule.MatchAllPorts = false
				ingressRule.Ports, ingressRule.NamedPorts = npc.processNetworkPolicyPorts(specIngressRule.Ports, namedPort2IngressEps)
			}

			newPolicy.IngressRules = append(newPolicy.IngressRules, ingressRule)
		}

		for _, specEgressRule := range policy.Spec.Egress {
			egressRule := EgressRule{}
			egressRule.DstPods = make([]PodInfo, 0)
			egressRule.DstIPBlocks = make([]*networking.IPBlock, 0)
			namedPort2EgressEps := make(namedPort2eps)

			// If this field is empty or missing in the spec, this rule matches all sources
			if len(specEgressRule.To) == 0 {
				egressRule.MatchAllDestinations = true
			} else {
				egressRule.MatchAllDestinations = false
				for _, peer := range specEgressRule.To {
					if ipBlockPeer := npc.evalIPBlockPeer(peer); ipBlockPeer != nil {
						egressRule.DstIPBlocks = append(egressRule.DstIPBlocks, ipBlockPeer)
					}

					if peer.NamespaceSelector != nil || peer.PodSelector != nil {
						peerServices, err := npc.evalServicePeer(policy, peer)
						if err == nil{
							egressRule.DstPods = append(egressRule.DstPods, peerServices...)
						}
					}

					peerPods, err := npc.evalPodPeer(policy, peer)
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
							npc.grabNamedPortFromPod(peerPod, &namedPort2EgressEps)
						}
					} else {
						glog.Errorf("Error evaluating pod peers for egress rule: %s", err.Error())
					}
				}
			}

			egressRule.Ports = make([]ProtocolAndPort, 0)
			egressRule.NamedPorts = make([]EndPoints, 0)
			// If this field is empty or missing in the spec, this rule matches all ports
			if len(specEgressRule.Ports) == 0 {
				egressRule.MatchAllPorts = true
			} else {
				egressRule.MatchAllPorts = false
				egressRule.Ports, egressRule.NamedPorts = npc.processNetworkPolicyPorts(specEgressRule.Ports, namedPort2EgressEps)
			}

			newPolicy.EgressRules = append(newPolicy.EgressRules, egressRule)
		}
		NetworkPolicies = append(NetworkPolicies, newPolicy)
	}

	return &NetworkPolicies, nil
}

func (npc *NetworkPolicyController) evalServicePeer(policy *networking.NetworkPolicy, peer networking.NetworkPolicyPeer) ([]PodInfo, error) {
	var namespaces []string
	var err error
	var podSelectorMatch map[string]string
	targetIPs := make([]PodInfo, 0)

	if peer.NamespaceSelector != nil {
		glog.V(6).Infof("Matching namespaceSelector %q for services in policy %s/%s",
			peer.NamespaceSelector, policy.Namespace, policy.Name)
		namespaces, err = func(matchLabels labels.Set) ([]string, error) {
			namespacesString := make([]string, 0)
			namespaces, err := npc.ListNamespaceByLabels(peer.NamespaceSelector.MatchLabels)
			if err == nil {
				for _, namespace := range namespaces {
					glog.V(6).Infof("Found namespace %s for policy %s/%s",
						namespace.Name, policy.Namespace, policy.Name)
					namespacesString = append(namespacesString, namespace.Name)
				}
				return namespacesString, nil
			} else {
				return nil, err
			}
		}(peer.NamespaceSelector.MatchLabels)

		if err != nil {
			return nil, errors.New("Failed to build network policies info due to " + err.Error())
		}
	} else {
		namespaces = append(namespaces, policy.Namespace)
	}

	if peer.PodSelector != nil {
		podSelectorMatch = peer.PodSelector.MatchLabels
	} else {
		podSelectorMatch = make(map[string]string, 0)
	}

	glog.V(6).Infof("Matching pods for services in namespaces %q for policy %s/%s",
		namespaces, policy.Namespace, policy.Name)
	for _, namespace := range namespaces {
		namespaceServices, err := npc.ListServicesByNamespaceAndLabels(namespace, podSelectorMatch)
		glog.V(6).Infof("Matched %d services for podSelector %q in namespace %s for policy %s/%s",
			len(namespaceServices), podSelectorMatch, namespace, policy.Namespace, policy.Name)
		if err != nil {
			return nil, errors.New("Failed to build network policies info due to " + err.Error())
		}
		for _, peerService := range namespaceServices {
			glog.V(6).Infof("Building IP list for policy %s/%s for service %s/%s",
				policy.Namespace, policy.Name, namespace, peerService.Name)
			if peerService.Spec.ClusterIP != "" && peerService.Spec.ClusterIP != "None" {
				glog.V(6).Infof("Adding clusterIP %s to service %s for policy %s/%s",
					peerService.Spec.ClusterIP, peerService.Name, policy.Namespace, policy.Name)
				targetIPs = append(targetIPs,
					PodInfo{IP: peerService.Spec.ClusterIP,
						Name:      peerService.ObjectMeta.Name,
						Namespace: peerService.ObjectMeta.Namespace,
						Labels:    peerService.ObjectMeta.Labels})

			}
			for _, externalIP := range peerService.Spec.ExternalIPs {
				if externalIP != "" && externalIP != "None" {
					glog.V(6).Infof("Adding externalIP %s to service %s for policy %s/%s",
						externalIP, peerService.Name, policy.Namespace, policy.Name)
					targetIPs = append(targetIPs,
						PodInfo{IP: externalIP,
							Name:      peerService.ObjectMeta.Name,
							Namespace: peerService.ObjectMeta.Namespace,
							Labels:    peerService.ObjectMeta.Labels})
				}
			}
		}
	}

	return targetIPs, nil
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

func (npc *NetworkPolicyController) ListServicesByNamespaceAndLabels(namespace string, labelsToMatch labels.Set) (ret []*api.Service, err error) {
	serviceLister := listers.NewServiceLister(npc.serviceLister)
	allMatchedNameSpaceServices, err := serviceLister.Services(namespace).List(labelsToMatch.AsSelector())
	if err != nil {
		return nil, err
	}
	return allMatchedNameSpaceServices, nil
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

func (npc *NetworkPolicyController) grabNamedPortFromPod(pod *api.Pod, namedPortToEndpoints *NamedPortToEndpoints) {
	if pod == nil || namedPortToEndpoints == nil {
		return
	}
	for k := range pod.Spec.Containers {
		for _, port := range pod.Spec.Containers[k].Ports {
			name := port.Name
			protocol := string(port.Protocol)
			containerPort := strconv.Itoa(int(port.ContainerPort))

			if (*namedPortToEndpoints)[name] == nil {
				(*namedPortToEndpoints)[name] = make(ProtocolToEndpoints)
			}
			if (*namedPortToEndpoints)[name][protocol] == nil {
				(*namedPortToEndpoints)[name][protocol] = make(NumericPortToEndpoints)
			}
			if eps, ok := (*namedPortToEndpoints)[name][protocol][containerPort]; !ok {
				(*namedPortToEndpoints)[name][protocol][containerPort] = &EndPoints{
					ips:             []string{pod.Status.PodIP},
					ProtocolAndPort: ProtocolAndPort{Port: containerPort, Protocol: protocol},
				}
			} else {
				eps.ips = append(eps.ips, pod.Status.PodIP)
			}
		}
	}
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
		namedPort2IngressEps := make(NamedPortToEndpoints)
		if err == nil {
			for _, matchingPod := range matchingPods {
				if matchingPod.Status.PodIP == "" {
					continue
				}
				newPolicy.TargetPods[matchingPod.Status.PodIP] = PodInfo{IP: matchingPod.Status.PodIP,
					Name:      matchingPod.ObjectMeta.Name,
					Namespace: matchingPod.ObjectMeta.Namespace,
					Labels:    matchingPod.ObjectMeta.Labels}
				npc.grabNamedPortFromPod(matchingPod, &namedPort2IngressEps)
			}
		}

		for _, specIngressRule := range policy.Spec.Ingress {
			ingressRule := IngressRule{}

			ingressRule.Ports = make([]ProtocolAndPort, 0)
			ingressRule.NamedPorts = make([]EndPoints, 0)
			ingressRule.Ports, ingressRule.NamedPorts = npc.processBetaNetworkPolicyPorts(specIngressRule.Ports, namedPort2IngressEps)
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

func (npc *NetworkPolicyController) newServiceEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			npc.OnServiceUpdate(obj)

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			npc.OnServiceUpdate(newObj)

		},
		DeleteFunc: func(obj interface{}) {
			npc.OnServiceUpdate(obj)

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
	config *options.KubeRouterConfig,
	podInformer cache.SharedIndexInformer,
	serviceInformer cache.SharedIndexInformer,
	npInformer cache.SharedIndexInformer,
	nsInformer cache.SharedIndexInformer) (*NetworkPolicyController, error) {
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

	npc.serviceLister = serviceInformer.GetIndexer()
	npc.ServiceEventHandler = npc.newServiceEventHandler()

	npc.nsLister = nsInformer.GetIndexer()
	npc.NamespaceEventHandler = npc.newNamespaceEventHandler()

	npc.npLister = npInformer.GetIndexer()
	npc.NetworkPolicyEventHandler = npc.newNetworkPolicyEventHandler()

	podCidr, err := utils.GetPodCidrFromNodeSpec(clientset, config.HostnameOverride)
	if err != nil {
		return nil, err
	}
	defaultDeny := config.NetworkPolicyDefault == "deny"

	iptables, err := NewIPTablesHandler(podCidr, defaultDeny)
	if err != nil {
		return nil, err
	}
	nftables, err := NewNFTablesHandler(podCidr, defaultDeny)
	if err != nil {
		return nil, err
	}
	if config.NetworkPolicyHandler == "nftables" {
		iptables.Cleanup()
		npc.handler = nftables
	} else {
		nftables.Cleanup()
		npc.handler = iptables
	}
	npc.handler.Init()

	return &npc, nil
}

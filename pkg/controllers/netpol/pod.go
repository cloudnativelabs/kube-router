package netpol

import (
	"crypto/sha256"
	"encoding/base32"
	"reflect"
	"strings"

	api "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

func (npc *NetworkPolicyController) newPodEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			npc.OnPodUpdate(obj)

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newPodObj := newObj.(*api.Pod)
			oldPodObj := oldObj.(*api.Pod)
			if newPodObj.Status.Phase != oldPodObj.Status.Phase ||
				newPodObj.Status.PodIP != oldPodObj.Status.PodIP ||
				!reflect.DeepEqual(newPodObj.Labels, oldPodObj.Labels) {
				// for the network policies, we are only interested in pod status phase change or IP change
				npc.OnPodUpdate(newObj)
			}
		},
		DeleteFunc: func(obj interface{}) {
			npc.handlePodDelete(obj)
		},
	}
}

// OnPodUpdate handles updates to pods from the Kubernetes api server
func (npc *NetworkPolicyController) OnPodUpdate(obj interface{}) {
	pod := obj.(*api.Pod)
	if pod.Spec.HostNetwork {
		klog.V(2).Info("Ignoring update to hostNetwork pod: %s/%s", pod.Namespace, pod.Name)
		return
	}
	klog.V(2).Infof("Received update to pod: %s/%s", pod.Namespace, pod.Name)

	npc.RequestFullSync()
}

func (npc *NetworkPolicyController) handlePodDelete(obj interface{}) {
	pod, ok := obj.(*api.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("unexpected object type: %v", obj)
			return
		}
		if pod, ok = tombstone.Obj.(*api.Pod); !ok {
			klog.Errorf("unexpected object type: %v", obj)
			return
		}
	}
	klog.V(2).Infof("Received pod: %s/%s delete event", pod.Namespace, pod.Name)

	npc.RequestFullSync()
}

func (npc *NetworkPolicyController) syncPodFirewallChains(networkPoliciesInfo []networkPolicyInfo, version string) (map[string]bool, error) {

	activePodFwChains := make(map[string]bool)

	dropUnmarkedTrafficRules := func(podName, podNamespace, podFwChainName string) error {
		// add rule to log the packets that will be dropped due to network policy enforcement
		comment := "\"rule to log dropped traffic POD name:" + podName + " namespace: " + podNamespace + "\""
		args := []string{"-A", podFwChainName, "-m", "comment", "--comment", comment, "-m", "mark", "!", "--mark", "0x10000/0x10000", "-j", "NFLOG", "--nflog-group", "100", "-m", "limit", "--limit", "10/minute", "--limit-burst", "10", "\n"}
		// This used to be AppendUnique when we were using iptables directly, this checks to make sure we didn't drop unmarked for this chain already
		if strings.Contains(npc.filterTableRules.String(), strings.Join(args, " ")) {
			return nil
		}
		npc.filterTableRules.WriteString(strings.Join(args, " "))

		// add rule to DROP if no applicable network policy permits the traffic
		comment = "\"rule to REJECT traffic destined for POD name:" + podName + " namespace: " + podNamespace + "\""
		args = []string{"-A", podFwChainName, "-m", "comment", "--comment", comment, "-m", "mark", "!", "--mark", "0x10000/0x10000", "-j", "REJECT", "\n"}
		npc.filterTableRules.WriteString(strings.Join(args, " "))

		// reset mark to let traffic pass through rest of the chains
		args = []string{"-A", podFwChainName, "-j", "MARK", "--set-mark", "0/0x10000", "\n"}
		npc.filterTableRules.WriteString(strings.Join(args, " "))

		return nil
	}

	// loop through the pods running on the node which to which ingress network policies to be applied
	ingressNetworkPolicyEnabledPods, err := npc.getIngressNetworkPolicyEnabledPods(networkPoliciesInfo, npc.nodeIP.String())
	if err != nil {
		return nil, err
	}
	for _, pod := range *ingressNetworkPolicyEnabledPods {

		// below condition occurs when we get trasient update while removing or adding pod
		// subseqent update will do the correct action
		if len(pod.ip) == 0 || pod.ip == "" {
			continue
		}

		// ensure pod specific firewall chain exist for all the pods that need ingress firewall
		podFwChainName := podFirewallChainName(pod.namespace, pod.name, version)
		npc.filterTableRules.WriteString(":" + podFwChainName + "\n")

		activePodFwChains[podFwChainName] = true

		// add entries in pod firewall to run through required network policies
		for _, policy := range networkPoliciesInfo {
			if _, ok := policy.targetPods[pod.ip]; ok {
				comment := "\"run through nw policy " + policy.name + "\""
				policyChainName := networkPolicyChainName(policy.namespace, policy.name, version)
				args := []string{"-I", podFwChainName, "1", "-m", "comment", "--comment", comment, "-j", policyChainName, "\n"}
				npc.filterTableRules.WriteString(strings.Join(args, " "))
			}
		}

		comment := "\"rule to permit the traffic traffic to pods when source is the pod's local node\""
		args := []string{"-I", podFwChainName, "1", "-m", "comment", "--comment", comment, "-m", "addrtype", "--src-type", "LOCAL", "-d", pod.ip, "-j", "ACCEPT", "\n"}
		npc.filterTableRules.WriteString(strings.Join(args, " "))

		// ensure statefull firewall, that permits return traffic for the traffic originated by the pod
		comment = "\"rule for stateful firewall for pod\""
		args = []string{"-I", podFwChainName, "1", "-m", "comment", "--comment", comment, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT", "\n"}
		npc.filterTableRules.WriteString(strings.Join(args, " "))

		// ensure there is rule in filter table and FORWARD chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting routed (coming for other node pods)
		comment = "\"rule to jump traffic destined to POD name:" + pod.name + " namespace: " + pod.namespace +
			" to chain " + podFwChainName + "\""
		args = []string{"-I", kubeForwardChainName, "1", "-m", "comment", "--comment", comment, "-d", pod.ip, "-j", podFwChainName + "\n"}
		npc.filterTableRules.WriteString(strings.Join(args, " "))

		// ensure there is rule in filter table and OUTPUT chain to jump to pod specific firewall chain
		// this rule applies to the traffic from a pod getting routed back to another pod on same node by service proxy
		args = []string{"-I", kubeOutputChainName, "1", "-m", "comment", "--comment", comment, "-d", pod.ip, "-j", podFwChainName + "\n"}
		npc.filterTableRules.WriteString(strings.Join(args, " "))

		// ensure there is rule in filter table and forward chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting switched (coming for same node pods)
		comment = "\"rule to jump traffic destined to POD name:" + pod.name + " namespace: " + pod.namespace +
			" to chain " + podFwChainName + "\""
		args = []string{"-I", kubeForwardChainName, "1", "-m", "physdev", "--physdev-is-bridged",
			"-m", "comment", "--comment", comment,
			"-d", pod.ip,
			"-j", podFwChainName, "\n"}
		npc.filterTableRules.WriteString(strings.Join(args, " "))

		err = dropUnmarkedTrafficRules(pod.name, pod.namespace, podFwChainName)
		if err != nil {
			return nil, err
		}
	}

	// loop through the pods running on the node which egress network policies to be applied
	egressNetworkPolicyEnabledPods, err := npc.getEgressNetworkPolicyEnabledPods(networkPoliciesInfo, npc.nodeIP.String())
	if err != nil {
		return nil, err
	}
	for _, pod := range *egressNetworkPolicyEnabledPods {

		// below condition occurs when we get trasient update while removing or adding pod
		// subseqent update will do the correct action
		if len(pod.ip) == 0 || pod.ip == "" {
			continue
		}

		// ensure pod specific firewall chain exist for all the pods that need egress firewall
		podFwChainName := podFirewallChainName(pod.namespace, pod.name, version)
		if !activePodFwChains[podFwChainName] {
			npc.filterTableRules.WriteString(":" + podFwChainName + "\n")
		}
		activePodFwChains[podFwChainName] = true

		// add entries in pod firewall to run through required network policies
		for _, policy := range networkPoliciesInfo {
			if _, ok := policy.targetPods[pod.ip]; ok {
				comment := "\"run through nw policy " + policy.name + "\""
				policyChainName := networkPolicyChainName(policy.namespace, policy.name, version)
				args := []string{"-I", podFwChainName, "1", "-m", "comment", "--comment", comment, "-j", policyChainName, "\n"}
				npc.filterTableRules.WriteString(strings.Join(args, " "))
			}
		}

		// ensure statefull firewall, that permits return traffic for the traffic originated by the pod
		comment := "\"rule for stateful firewall for pod\""
		args := []string{"-I", podFwChainName, "1", "-m", "comment", "--comment", comment, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT", "\n"}
		npc.filterTableRules.WriteString(strings.Join(args, " "))

		egressFilterChains := []string{kubeInputChainName, kubeForwardChainName, kubeOutputChainName}
		for _, chain := range egressFilterChains {
			// ensure there is rule in filter table and FORWARD chain to jump to pod specific firewall chain
			// this rule applies to the traffic getting forwarded/routed (traffic from the pod destinted
			// to pod on a different node)
			comment = "\"rule to jump traffic from POD name:" + pod.name + " namespace: " + pod.namespace +
				" to chain " + podFwChainName + "\""
			args = []string{"-A", chain, "-m", "comment", "--comment", comment, "-s", pod.ip, "-j", podFwChainName, "\n"}
			npc.filterTableRules.WriteString(strings.Join(args, " "))
		}

		// ensure there is rule in filter table and forward chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting switched (coming for same node pods)
		comment = "\"rule to jump traffic from POD name:" + pod.name + " namespace: " + pod.namespace +
			" to chain " + podFwChainName + "\""
		args = []string{"-I", kubeForwardChainName, "1", "-m", "physdev", "--physdev-is-bridged",
			"-m", "comment", "--comment", comment,
			"-s", pod.ip,
			"-j", podFwChainName, "\n"}
		npc.filterTableRules.WriteString(strings.Join(args, " "))

		err = dropUnmarkedTrafficRules(pod.name, pod.namespace, podFwChainName)
		if err != nil {
			return nil, err
		}
	}

	return activePodFwChains, nil
}

func (npc *NetworkPolicyController) getIngressNetworkPolicyEnabledPods(networkPoliciesInfo []networkPolicyInfo, nodeIP string) (*map[string]podInfo, error) {
	nodePods := make(map[string]podInfo)

	for _, obj := range npc.podLister.List() {
		pod := obj.(*api.Pod)

		if strings.Compare(pod.Status.HostIP, nodeIP) != 0 {
			continue
		}
		for _, policy := range networkPoliciesInfo {
			if policy.namespace != pod.ObjectMeta.Namespace {
				continue
			}
			_, ok := policy.targetPods[pod.Status.PodIP]
			if ok && (policy.policyType == "both" || policy.policyType == "ingress") {
				klog.V(2).Infof("Found pod name: " + pod.ObjectMeta.Name + " namespace: " + pod.ObjectMeta.Namespace + " for which network policies need to be applied.")
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

func (npc *NetworkPolicyController) getEgressNetworkPolicyEnabledPods(networkPoliciesInfo []networkPolicyInfo, nodeIP string) (*map[string]podInfo, error) {

	nodePods := make(map[string]podInfo)

	for _, obj := range npc.podLister.List() {
		pod := obj.(*api.Pod)

		if strings.Compare(pod.Status.HostIP, nodeIP) != 0 {
			continue
		}
		for _, policy := range networkPoliciesInfo {
			if policy.namespace != pod.ObjectMeta.Namespace {
				continue
			}
			_, ok := policy.targetPods[pod.Status.PodIP]
			if ok && (policy.policyType == "both" || policy.policyType == "egress") {
				klog.V(2).Infof("Found pod name: " + pod.ObjectMeta.Name + " namespace: " + pod.ObjectMeta.Namespace + " for which network policies need to be applied.")
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

func podFirewallChainName(namespace, podName string, version string) string {
	hash := sha256.Sum256([]byte(namespace + podName + version))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubePodFirewallChainPrefix + encoded[:16]
}

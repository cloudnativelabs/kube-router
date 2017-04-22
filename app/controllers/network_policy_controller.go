package controllers

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/app/options"
	"github.com/cloudnativelabs/kube-router/app/watchers"
	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
	"github.com/janeczku/go-ipset/ipset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	apiv1 "k8s.io/client-go/pkg/api/v1"
)

// Network policy controller provides an ingress firewall for the pods as per the defined network policies.
// Two different types of iptables chains are used. Each pod running on the node which has default ingress
// policy is to deny the traffic gets a pod specific chian. Each network policy has a iptable chain, which
// has rules expreessed through ipsets matching source and destination pod ip's. In the FORWARD chain of the
// filter table a rule is added jump the traffic destined to the pod to the pod specific iptable chain. Each
// pod specifc iptable chain has rules to jump to the network polices chains, that pod matches. So packet
// destined for pod goes throuh fitler table's, FORWARD chain, followed by pod specific chain, followed
// by one or more network policy chains, till there is a match which will accept the packet, or gets
// dropped by the rule in the pod chain, if there is no match.

type NetworkPolicyController struct {
	nodeIP       net.IP
	nodeHostName string
	mu           sync.Mutex
	syncPeriod   time.Duration

	// list of all active network policies expressed as networkPolicyInfo
	networkPoliciesInfo *[]networkPolicyInfo
}

// internal structure to represent a network policy
type networkPolicyInfo struct {
	name      string
	namespace string
	labels    map[string]string

	// set of pods matching network policy spec podselector label selector
	destPods map[string]podInfo

	// whitelist ingress rules from the netwrok policy spec
	ingressRules []ingressRule
}

// internal structure to represent Pod
type podInfo struct {
	ip        string
	name      string
	namespace string
	labels    map[string]string
}

type ingressRule struct {
	ports   []protocolAndPort
	srcPods []podInfo
}

type protocolAndPort struct {
	protocol string
	port     string
}

func (npc *NetworkPolicyController) Run(stopCh <-chan struct{}, wg *sync.WaitGroup) {
	t := time.NewTicker(npc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	glog.Infof("Starting network policy controller")

	// loop forever till notified to stop on stopCh
	for {
		select {
		case <-stopCh:
			glog.Infof("Shutting down network policies controller")
			return
		default:
		}

		if watchers.PodWatcher.HasSynced() && watchers.NetworkPolicyWatcher.HasSynced() {
			glog.Infof("Performing periodic syn of the iptables to reflect network policies")
			npc.Sync()
		} else {
			continue
		}

		select {
		case <-stopCh:
			glog.Infof("Shutting down network policies controller")
			return
		case <-t.C:
		}
	}
}

func (npc *NetworkPolicyController) OnPodUpdate(podUpdate *watchers.PodUpdate) {
	glog.Infof("Received pod update namspace:%s pod name:%s", podUpdate.Pod.Namespace, podUpdate.Pod.Name)
	if watchers.PodWatcher.HasSynced() && watchers.NetworkPolicyWatcher.HasSynced() {
		npc.Sync()
	} else {
		glog.Infof("Received pod update, but controller not in sync")
	}
}

func (npc *NetworkPolicyController) OnNetworkPolicyUpdate(networkPolicyUpdate *watchers.NetworkPolicyUpdate) {
	glog.Infof("Received network policy update namspace:%s policy name:%s", networkPolicyUpdate.NetworkPolicy.Namespace, networkPolicyUpdate.NetworkPolicy.Name)
	if watchers.PodWatcher.HasSynced() && watchers.NetworkPolicyWatcher.HasSynced() {
		npc.Sync()
	} else {
		glog.Infof("Received network policy update, but controller not in sync")
	}
}

func (npc *NetworkPolicyController) OnNamespaceUpdate(namespaceUpdate *watchers.NamespaceUpdate) {
	glog.Infof("Received namesapce update namspace:%s", namespaceUpdate.Namespace.Name)
	if watchers.PodWatcher.HasSynced() && watchers.NetworkPolicyWatcher.HasSynced() {
		npc.Sync()
	} else {
		glog.Infof("Received namspace update, but controller not in sync")
	}
}

// Sync synchronizes iptables to desired state of network policies
func (npc *NetworkPolicyController) Sync() {

	var err error
	npc.mu.Lock()
	defer npc.mu.Unlock()

	start := time.Now()
	defer func() {
		glog.Infof("sync iptables took %v", time.Since(start))
	}()

	npc.networkPoliciesInfo, err = buildNetworkPoliciesInfo()
	if err != nil {
		glog.Errorf("Aborting sync. Failed to build network policies: %s", err.Error())
		return
	}

	activePolicyChains, err := npc.syncNetworkPolicyChains()
	if err != nil {
		glog.Errorf("Aborting sync. Failed to sync network policy chains: %s", err.Error())
		return
	}

	activePodFwChains, err := npc.syncPodFirewallChains()
	if err != nil {
		glog.Errorf("Aborting sync. Failed to sync pod firewalls: %s", err.Error())
		return
	}

	err = cleanupStaleRules(activePolicyChains, activePodFwChains)
	if err != nil {
		glog.Errorf("Aborting sync. Failed to cleanup stale iptable rules: %s", err.Error())
		return
	}
}

// Configure iptable rules representing each network policy. All pod's matched by
// network policy spec podselector labels are grouped together in one ipset which
// is used for matching destination ip address. Each ingress rule in the network
// policyspec is evaluated to set of matching pods, which are grouped in to a
// ipset used for source ip addr matching.
func (npc *NetworkPolicyController) syncNetworkPolicyChains() (map[string]bool, error) {

	activePolicyChains := make(map[string]bool)

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		glog.Fatalf("Failed to initialize iptables executor due to: %s", err.Error())
	}

	// run through all network policies
	for _, policy := range *npc.networkPoliciesInfo {

		// ensure there is a unique chain per network policy in filter table
		policyChainName := networkPolicyChainName(policy.namespace, policy.name)
		err := iptablesCmdHandler.NewChain("filter", policyChainName)
		if err != nil && err.(*iptables.Error).ExitStatus() != 1 {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}

		activePolicyChains[policyChainName] = true

		// create a ipset for all destination pod ip's matched by the policy spec PodSelector
		destPodIpSetName := policyDestinationPodIpSetName(policy.namespace, policy.name)
		destPodIpSet, err := ipset.New(destPodIpSetName, "hash:ip", &ipset.Params{})
		if err != nil {
			return nil, fmt.Errorf("failed to create ipset: %s", err.Error())
		}

		// flush all entries in the set
		if destPodIpSet.Flush() != nil {
			return nil, fmt.Errorf("failed to flush ipset while syncing iptables: %s", err.Error())
		}
		for k, _ := range policy.destPods {
			// TODO restrict ipset to ip's of pods running on the node
			destPodIpSet.Add(k, 0)
		}

		// TODO use iptables-restore to better implement the logic, than flush and add rules
		err = iptablesCmdHandler.ClearChain("filter", policyChainName)
		if err != nil && err.(*iptables.Error).ExitStatus() != 1 {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}

		// run through all the ingress rules in the spec and create iptable rules
		// in the chain for the network policy
		for i, ingressRule := range policy.ingressRules {

			if len(ingressRule.srcPods) != 0 {
				srcPodIpSetName := policySourcePodIpSetName(policy.namespace, policy.name, i)
				srcPodIpSet, err := ipset.New(srcPodIpSetName, "hash:ip", &ipset.Params{})
				if err != nil {
					return nil, fmt.Errorf("failed to create ipset: %s", err.Error())
				}
				// flush all entries in the set
				if srcPodIpSet.Flush() != nil {
					return nil, fmt.Errorf("failed to flush ipset while syncing iptables: %s", err.Error())
				}

				for _, pod := range ingressRule.srcPods {
					srcPodIpSet.Add(pod.ip, 0)
				}

				if len(ingressRule.ports) != 0 {
					// case where 'ports' details and 'from' details specified in the ingress rule
					// so match on specified source and destination ip's and specified port and protocol
					for _, portProtocol := range ingressRule.ports {
						comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
							policy.name + " namespace " + policy.namespace
						args := []string{"-m", "comment", "--comment", comment,
							"-m", "set", "--set", srcPodIpSetName, "src",
							"-m", "set", "--set", destPodIpSetName, "dst",
							"-p", portProtocol.protocol,
							"--dport", portProtocol.port,
							"-j", "ACCEPT"}
						err := iptablesCmdHandler.AppendUnique("filter", policyChainName, args...)
						if err != nil {
							return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
						}
					}
				} else {
					// case where no 'ports' details specified in the ingress rule but 'from' details specified
					// so match on specified source and destination ip with all port and protocol
					comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
						policy.name + " namespace " + policy.namespace
					args := []string{"-m", "comment", "--comment", comment,
						"-m", "set", "--set", srcPodIpSetName, "src",
						"-m", "set", "--set", destPodIpSetName, "dst",
						"-j", "ACCEPT"}
					err := iptablesCmdHandler.AppendUnique("filter", policyChainName, args...)
					if err != nil {
						return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
					}
				}
			}

			// case where only 'ports' details specified but no 'from' details in the ingress rule
			// so match on all sources, with specified port and protocol
			if len(ingressRule.srcPods) == 0 && len(ingressRule.ports) != 0 {
				for _, portProtocol := range ingressRule.ports {
					comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name: " +
						policy.name + " namespace " + policy.namespace
					args := []string{"-m", "comment", "--comment", comment,
						"-m", "set", "--set", destPodIpSetName, "dst",
						"-p", portProtocol.protocol,
						"--dport", portProtocol.port,
						"-j", "ACCEPT"}
					err := iptablesCmdHandler.AppendUnique("filter", policyChainName, args...)
					if err != nil {
						return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
					}
				}
			}

			// case where nether ports nor from details are speified in the ingress rule
			// so match on all ports, protocol, source IP's
			if len(ingressRule.srcPods) == 0 && len(ingressRule.ports) == 0 {
				comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				args := []string{"-m", "comment", "--comment", comment,
					"-m", "set", "--set", destPodIpSetName, "dst",
					"-j", "ACCEPT"}
				err := iptablesCmdHandler.AppendUnique("filter", policyChainName, args...)
				if err != nil {
					return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
				}
			}
		}
	}

	glog.Infof("Iptables chains in the filter table are synchronized with the network policies.")

	return activePolicyChains, nil
}

func (npc *NetworkPolicyController) syncPodFirewallChains() (map[string]bool, error) {

	activePodFwChains := make(map[string]bool)

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		glog.Fatalf("Failed to initialize iptables executor: %s", err.Error())
	}

	// loop through the pods running on the node which has default ingress to be denied
	podsOnNodeInfo, err := getPodsRunningOnNode(npc.nodeIP.String())
	for _, pod := range *podsOnNodeInfo {

		// below condition occurs when we get trasient update while removing or adding pod
		// subseqent update will do the correct action
		if len(pod.ip) == 0 || pod.ip == "" {
			continue
		}

		// ensure pod specfic firewall chain exist for all the pods running on this node
		podFwChainName := podFirewallChainName(pod.namespace, pod.name)
		err = iptablesCmdHandler.NewChain("filter", podFwChainName)
		if err != nil && err.(*iptables.Error).ExitStatus() != 1 {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		activePodFwChains[podFwChainName] = true

		// ensure there is rule in filter table and FORWARD chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting routed (coming for other node pods)
		comment := "rule to jump traffic destined to POD name:" + pod.name + " namespace: " + pod.namespace +
			" to chain " + podFwChainName
		args := []string{"-m", "comment", "--comment", comment, "-d", pod.ip, "-j", podFwChainName}
		exists, err := iptablesCmdHandler.Exists("filter", "FORWARD", args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err := iptablesCmdHandler.Insert("filter", "FORWARD", 1, args...)
			if err != nil {
				return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
			}
		}

		// ensure there is rule in filter table and OUTPUT chain to jump to pod specific firewall chain
		// this rule applies to the traffic from a pod getting routed back to another pod on same node by service proxy
		exists, err = iptablesCmdHandler.Exists("filter", "OUTPUT", args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err := iptablesCmdHandler.Insert("filter", "OUTPUT", 1, args...)
			if err != nil {
				return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
			}
		}

		// ensure there is rule in filter table and forward chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting switched (coming for same node pods)
		comment = "rule to jump traffic destined to POD name:" + pod.name + " namespace: " + pod.namespace +
			" to chain " + podFwChainName
		args = []string{"-m", "physdev", "--physdev-is-bridged",
			"-m", "comment", "--comment", comment,
			"-d", pod.ip,
			"-j", podFwChainName}
		exists, err = iptablesCmdHandler.Exists("filter", "FORWARD", args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err = iptablesCmdHandler.Insert("filter", "FORWARD", 1, args...)
			if err != nil {
				return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
			}
		}

		// add default DROP rule at the end of chain
		comment = "default rule to REJECT traffic destined for POD name:" + pod.name + " namespace: " + pod.namespace
		args = []string{"-m", "comment", "--comment", comment, "-j", "REJECT"}
		err = iptablesCmdHandler.AppendUnique("filter", podFwChainName, args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}

		// add entries in pod firewall to run through required network policies
		for _, policy := range *npc.networkPoliciesInfo {
			if _, ok := policy.destPods[pod.ip]; ok {
				comment := "run through nw policy " + policy.name
				policyChainName := networkPolicyChainName(policy.namespace, policy.name)
				args := []string{"-m", "comment", "--comment", comment, "-j", policyChainName}
				exists, err := iptablesCmdHandler.Exists("filter", podFwChainName, args...)
				if err != nil {
					return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
				}
				if !exists {
					err := iptablesCmdHandler.Insert("filter", podFwChainName, 1, args...)
					if err != nil && err.(*iptables.Error).ExitStatus() != 1 {
						return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
					}
				}
			}
		}

		// ensure statefull firewall, that permits return traffic for the traffic originated by the pod
		comment = "rule for stateful firewall for pod"
		args = []string{"-m", "comment", "--comment", comment, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
		exists, err = iptablesCmdHandler.Exists("filter", podFwChainName, args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err := iptablesCmdHandler.Insert("filter", podFwChainName, 1, args...)
			if err != nil {
				return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
			}
		}
	}

	return activePodFwChains, nil
}

func cleanupStaleRules(activePolicyChains, activePodFwChains map[string]bool) error {

	cleanupPodFwChains := make([]string, 0)
	cleanupPolicyChains := make([]string, 0)

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		glog.Fatalf("failed to initialize iptables command executor due to %s", err.Error())
	}

	// get the list of chains created for pod firewall and network policies
	chains, err := iptablesCmdHandler.ListChains("filter")
	for _, chain := range chains {
		if strings.HasPrefix(chain, "KUBE-NWPLCY-") {
			if _, ok := activePolicyChains[chain]; !ok {
				cleanupPolicyChains = append(cleanupPolicyChains, chain)
			}
		}
		if strings.HasPrefix(chain, "KUBE-POD-FW-") {
			if _, ok := activePodFwChains[chain]; !ok {
				cleanupPodFwChains = append(cleanupPodFwChains, chain)
			}
		}
	}

	// cleanup FORWARD chain rules to jump to pod firewall
	for _, chain := range cleanupPodFwChains {

		forwardChainRules, err := iptablesCmdHandler.List("filter", "FORWARD")
		if err != nil {
			return fmt.Errorf("failed to list rules in filter table, FORWARD chain due to %s", err.Error())
		}
		outputChainRules, err := iptablesCmdHandler.List("filter", "OUTPUT")
		if err != nil {
			return fmt.Errorf("failed to list rules in filter table, OUTPUT chain due to %s", err.Error())
		}

		// TODO delete rule by spec, than rule number to avoid extra loop
		var realRuleNo int = 0
		for i, rule := range forwardChainRules {
			if strings.Contains(rule, chain) {
				err = iptablesCmdHandler.Delete("filter", "FORWARD", strconv.Itoa(i-realRuleNo))
				if err != nil {
					return fmt.Errorf("failed to delete rule: %s from the FORWARD chain of filter table due to %s", rule, err.Error())
				}
				realRuleNo++
			}
		}
		realRuleNo = 0
		for i, rule := range outputChainRules {
			if strings.Contains(rule, chain) {
				err = iptablesCmdHandler.Delete("filter", "OUTPUT", strconv.Itoa(i-realRuleNo))
				if err != nil {
					return fmt.Errorf("failed to delete rule: %s from the OUTPUT chain of filter table due to %s", rule, err.Error())
				}
				realRuleNo++
			}
		}
	}

	// cleanup pod firewall chain
	for _, chain := range cleanupPodFwChains {
		glog.Errorf("Found pod fw chain to cleanup: %s", chain)
		err = iptablesCmdHandler.ClearChain("filter", chain)
		if err != nil {
			return fmt.Errorf("Failed to flush the rules in chain %s due to %s", chain, err.Error())
		}
		err = iptablesCmdHandler.DeleteChain("filter", chain)
		if err != nil {
			return fmt.Errorf("Failed to delete the chain %s due to %s", chain, err.Error())
		}
		glog.Infof("Deleted pod specific firewall chain: %s from the filter table", chain)
	}

	// cleanup network policy chains
	for _, policyChain := range cleanupPolicyChains {
		glog.Infof("Found policy chain to cleanup %s", policyChain)

		// first clean up any references from pod firewall chain
		for podFwChain := range activePodFwChains {
			podFwChainRules, err := iptablesCmdHandler.List("filter", podFwChain)
			if err != nil {

			}
			for i, rule := range podFwChainRules {
				if strings.Contains(rule, policyChain) {
					err = iptablesCmdHandler.Delete("filter", podFwChain, strconv.Itoa(i))
					if err != nil {
						return fmt.Errorf("Failed to delete rule %s from the chain %s", rule, podFwChain)
					}
					break
				}
			}
		}

		err = iptablesCmdHandler.ClearChain("filter", policyChain)
		if err != nil {
			return fmt.Errorf("Failed to flush the rules in chain %s due to  %s", policyChain, err)
		}
		err = iptablesCmdHandler.DeleteChain("filter", policyChain)
		if err != nil {
			return fmt.Errorf("Failed to flush the rules in chain %s due to %s", policyChain, err)
		}
		glog.Infof("Deleted network policy chain: %s from the filter table", policyChain)
	}

	// TODO delete unused ipsets
	return nil
}

func getPodsRunningOnNode(nodeIp string) (*map[string]podInfo, error) {

	nodePods := make(map[string]podInfo)

	for _, pod := range watchers.PodWatcher.List() {
		if strings.Compare(pod.Status.HostIP, nodeIp) != 0 {
			continue
		}
		default_policy, err := getNameSpaceDefaultPolicy(pod.ObjectMeta.Namespace)
		if err != nil {
			return nil, fmt.Errorf("Failed to get the namespace default ingress policy %s", err.Error())
		}
		if strings.Compare(default_policy, "DefaultDeny") != 0 {
			continue
		}
		nodePods[pod.Status.PodIP] = podInfo{ip: pod.Status.PodIP,
			name:      pod.ObjectMeta.Name,
			namespace: pod.ObjectMeta.Namespace,
			labels:    pod.ObjectMeta.Labels}
	}
	return &nodePods, nil
}

func buildNetworkPoliciesInfo() (*[]networkPolicyInfo, error) {

	NetworkPolicies := make([]networkPolicyInfo, 0)

	for _, policy := range watchers.NetworkPolicyWatcher.List() {
		newPolicy := networkPolicyInfo{
			name:      policy.Name,
			namespace: policy.Namespace,
			labels:    policy.Spec.PodSelector.MatchLabels,
		}
		matchingPods, err := watchers.PodWatcher.ListByNamespaceAndLabels(policy.Namespace, policy.Spec.PodSelector.MatchLabels)
		newPolicy.destPods = make(map[string]podInfo)
		newPolicy.ingressRules = make([]ingressRule, 0)
		if err == nil {
			for _, matchingPod := range matchingPods {
				newPolicy.destPods[matchingPod.Status.PodIP] = podInfo{ip: matchingPod.Status.PodIP,
					name:      matchingPod.ObjectMeta.Name,
					namespace: matchingPod.ObjectMeta.Namespace,
					labels:    matchingPod.ObjectMeta.Labels}
			}
		}

		for _, specIngressRule := range policy.Spec.Ingress {
			ingressRule := ingressRule{}

			ingressRule.ports = make([]protocolAndPort, 0)
			for _, port := range specIngressRule.Ports {
				protocolAndPort := protocolAndPort{protocol: string(*port.Protocol), port: port.Port.String()}
				ingressRule.ports = append(ingressRule.ports, protocolAndPort)
			}

			ingressRule.srcPods = make([]podInfo, 0)
			for _, peer := range specIngressRule.From {
				matchingPods, err := watchers.PodWatcher.ListByNamespaceAndLabels(policy.Namespace, peer.PodSelector.MatchLabels)
				if err == nil {
					for _, matchingPod := range matchingPods {
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

func getNameSpaceDefaultPolicy(namespace string) (string, error) {
	for _, nspw := range watchers.NamespaceWatcher.List() {
		if strings.Compare(namespace, nspw.Name) == 0 {
			networkPolicyAnnotation, ok := nspw.ObjectMeta.Annotations["net.beta.kubernetes.io/network-policy"]
			var annot map[string]map[string]string
			if ok {
				err := json.Unmarshal([]byte(networkPolicyAnnotation), &annot)
				if err == nil {
					return annot["ingress"]["isolation"], nil
				}
			} else {
				return "DefaultAllow", nil
			}
		}
	}
	return "", errors.New("Failed to get the default ingress policy for the namespace: " + namespace)
}

func podFirewallChainName(namespace, podName string) string {
	hash := sha256.Sum256([]byte(namespace + podName))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return "KUBE-POD-FW-" + encoded[:16]
}

func networkPolicyChainName(namespace, policyName string) string {
	hash := sha256.Sum256([]byte(namespace + policyName))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return "KUBE-NWPLCY-" + encoded[:16]
}

func policyDestinationPodIpSetName(namespace, policyName string) string {
	hash := sha256.Sum256([]byte(namespace + policyName))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return "KUBE-DST-" + encoded[:16]
}

func policySourcePodIpSetName(namespace, policyName string, ingressRuleNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo)))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return "KUBE-SRC-" + encoded[:16]
}

func getNodeIP(node *apiv1.Node) (net.IP, error) {
	addresses := node.Status.Addresses
	addressMap := make(map[apiv1.NodeAddressType][]apiv1.NodeAddress)
	for i := range addresses {
		addressMap[addresses[i].Type] = append(addressMap[addresses[i].Type], addresses[i])
	}
	if addresses, ok := addressMap[apiv1.NodeInternalIP]; ok {
		return net.ParseIP(addresses[0].Address), nil
	}
	if addresses, ok := addressMap[apiv1.NodeExternalIP]; ok {
		return net.ParseIP(addresses[0].Address), nil
	}
	if addresses, ok := addressMap[apiv1.NodeLegacyHostIP]; ok {
		return net.ParseIP(addresses[0].Address), nil
	}
	return nil, errors.New("host IP unknown")
}

func (npc *NetworkPolicyController) Cleanup() {

	glog.Infof("Cleaning up iptables configuration permanently done by kube-router")

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		glog.Errorf("Failed to initialize iptables executor: %s", err.Error())
	}

	// delete jump rules in FORWARD chain to pod specific firewall chain
	forwardChainRules, err := iptablesCmdHandler.List("filter", "FORWARD")
	if err != nil {
		glog.Errorf("Failed to delete iptable rules as part of cleanup")
		return
	}

	// TODO: need a better way to delte rule with out using number
	var realRuleNo int = 0
	for i, rule := range forwardChainRules {
		if strings.Contains(rule, "KUBE-POD-FW-") {
			err = iptablesCmdHandler.Delete("filter", "FORWARD", strconv.Itoa(i-realRuleNo))
			realRuleNo++
		}
	}

	// delete jump rules in OUTPUT chain to pod specific firewall chain
	forwardChainRules, err = iptablesCmdHandler.List("filter", "OUTPUT")
	if err != nil {
		glog.Errorf("Failed to delete iptable rules as part of cleanup")
		return
	}

	// TODO: need a better way to delte rule with out using number
	realRuleNo = 0
	for i, rule := range forwardChainRules {
		if strings.Contains(rule, "KUBE-POD-FW-") {
			err = iptablesCmdHandler.Delete("filter", "OUTPUT", strconv.Itoa(i-realRuleNo))
			realRuleNo++
		}
	}

	// flush and delete pod specific firewall chain
	chains, err := iptablesCmdHandler.ListChains("filter")
	for _, chain := range chains {
		if strings.HasPrefix(chain, "KUBE-POD-FW-") {
			err = iptablesCmdHandler.ClearChain("filter", chain)
			if err != nil {
				glog.Errorf("Failed to cleanup iptable rules: " + err.Error())
				return
			}
			err = iptablesCmdHandler.DeleteChain("filter", chain)
			if err != nil {
				glog.Errorf("Failed to cleanup iptable rules: " + err.Error())
				return
			}
		}
	}

	// flush and delete per network policy specific chain
	chains, err = iptablesCmdHandler.ListChains("filter")
	for _, chain := range chains {
		if strings.HasPrefix(chain, "KUBE-NWPLCY-") {
			err = iptablesCmdHandler.ClearChain("filter", chain)
			if err != nil {
				glog.Errorf("Failed to cleanup iptable rules: " + err.Error())
				return
			}
			err = iptablesCmdHandler.DeleteChain("filter", chain)
			if err != nil {
				glog.Errorf("Failed to cleanup iptable rules: " + err.Error())
				return
			}
		}
	}

	// delete all ipsets
	err = ipset.DestroyAll()
	if err != nil {
		glog.Errorf("Failed to clean up ipsets: " + err.Error())
	}
	glog.Infof("Successfully cleaned the iptables configuration done by kube-router")
}

func init() {
	_, err := exec.LookPath("ipset")
	if err != nil {
		panic("ipset command not found ensure ipset package is installed")
	}
}

func NewNetworkPolicyController(clientset *kubernetes.Clientset, config *options.KubeRouterConfig) (*NetworkPolicyController, error) {

	npc := NetworkPolicyController{}

	npc.syncPeriod = config.IPTablesSyncPeriod

	nodeHostName, err := os.Hostname()
	if err != nil {
		panic(err.Error())
	}
	npc.nodeHostName = nodeHostName

	node, err := clientset.Core().Nodes().Get(nodeHostName, metav1.GetOptions{})
	if err != nil {
		panic(err.Error())
	}
	nodeIP, err := getNodeIP(node)
	if err != nil {
		panic(err.Error())
	}
	npc.nodeIP = nodeIP

	watchers.PodWatcher.RegisterHandler(&npc)
	watchers.NetworkPolicyWatcher.RegisterHandler(&npc)
	watchers.NamespaceWatcher.RegisterHandler(&npc)

	return &npc, nil
}

package netpol

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
	"k8s.io/api/networking/v1"
	"strconv"
	"strings"
	"time"
)

const (
	networkPolicyAnnotation      = "net.beta.kubernetes.io/network-policy"
	kubePodFirewallChainPrefix   = "KUBE-POD-FW-"
	kubeNetworkPolicyChainPrefix = "KUBE-NWPLCY-"
	kubeSourceIpSetPrefix        = "KUBE-SRC-"
	kubeDestinationIpSetPrefix   = "KUBE-DST-"
)

type IPTables struct {
	ipSetHandler *utils.IPSet
}

func NewIPTablesHandler(podCIDR string, defaultDeny bool) (*IPTables, error) {
	ipset, err := utils.NewIPSet(false)
	if err != nil {
		return nil, err
	}
	err = ipset.Save()
	if err != nil {
		return nil, err
	}

	return &IPTables{
		ipSetHandler: ipset,
	}, nil
}

func (nft *IPTables) Init() {
	// no-op
}

func (ipt *IPTables) Sync(networkPoliciesInfo *[]NetworkPolicyInfo, ingressPods, egressPods *map[string]PodInfo) error {

	start := time.Now()
	syncVersion := strconv.FormatInt(start.UnixNano(), 10)
	glog.V(1).Infof("Starting iptables sync with version: %s", syncVersion)

	activePolicyChains, activePolicyIpSets, err := ipt.syncNetworkPolicyChains(syncVersion, networkPoliciesInfo)
	if err != nil {
		return errors.New("Aborting sync. Failed to sync network policy chains: " + err.Error())
	}

	activePodFwChains, err := ipt.syncPodFirewallChains(syncVersion, networkPoliciesInfo, ingressPods, egressPods)
	if err != nil {
		return errors.New("Aborting sync. Failed to sync pod firewalls: " + err.Error())
	}

	err = cleanupStaleRules(activePolicyChains, activePodFwChains, activePolicyIpSets)
	if err != nil {
		return errors.New("Aborting sync. Failed to cleanup stale iptables rules: " + err.Error())
	}

	return nil
}

// Configure iptables rules representing each network policy. All pod's matched by
// network policy spec podselector labels are grouped together in one ipset which
// is used for matching destination ip address. Each ingress rule in the network
// policyspec is evaluated to set of matching pods, which are grouped in to a
// ipset used for source ip addr matching.
func (ipt *IPTables) syncNetworkPolicyChains(version string, networkPoliciesInfo *[]NetworkPolicyInfo) (map[string]bool, map[string]bool, error) {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		metrics.ControllerPolicyChainsSyncTime.Observe(endTime.Seconds())
		glog.V(2).Infof("Syncing network policy chains took %v", endTime)
	}()
	activePolicyChains := make(map[string]bool)
	activePolicyIpSets := make(map[string]bool)

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		glog.Fatalf("Failed to initialize iptables executor due to: %s", err.Error())
	}

	// run through all network policies
	for _, policy := range *networkPoliciesInfo {

		// ensure there is a unique chain per network policy in filter table
		policyChainName := networkPolicyChainName(policy.Namespace, policy.Name, version)
		err := iptablesCmdHandler.NewChain("filter", policyChainName)
		if err != nil && err.(*iptables.Error).ExitStatus() != 1 {
			return nil, nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}

		activePolicyChains[policyChainName] = true

		// create a ipset for all destination pod ip's matched by the policy spec PodSelector
		targetDestPodIpSetName := policyDestinationPodIpSetName(policy.Namespace, policy.Name)
		targetDestPodIpSet, err := ipt.ipSetHandler.Create(targetDestPodIpSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create ipset: %s", err.Error())
		}

		// create a ipset for all source pod ip's matched by the policy spec PodSelector
		targetSourcePodIpSetName := policySourcePodIpSetName(policy.Namespace, policy.Name)
		targetSourcePodIpSet, err := ipt.ipSetHandler.Create(targetSourcePodIpSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create ipset: %s", err.Error())
		}

		activePolicyIpSets[targetDestPodIpSet.Name] = true
		activePolicyIpSets[targetSourcePodIpSet.Name] = true

		currnetPodIps := make([]string, 0, len(policy.TargetPods))
		for ip := range policy.TargetPods {
			currnetPodIps = append(currnetPodIps, ip)
		}

		err = targetSourcePodIpSet.Refresh(currnetPodIps, utils.OptionTimeout, "0")
		if err != nil {
			glog.Errorf("failed to refresh targetSourcePodIpSet: " + err.Error())
		}
		err = targetDestPodIpSet.Refresh(currnetPodIps, utils.OptionTimeout, "0")
		if err != nil {
			glog.Errorf("failed to refresh targetDestPodIpSet: " + err.Error())
		}

		err = ipt.processIngressRules(policy, targetDestPodIpSetName, activePolicyIpSets, version)
		if err != nil {
			return nil, nil, err
		}

		err = ipt.processEgressRules(policy, targetSourcePodIpSetName, activePolicyIpSets, version)
		if err != nil {
			return nil, nil, err
		}
	}

	glog.V(2).Infof("Iptables chains in the filter table are synchronized with the network policies.")

	return activePolicyChains, activePolicyIpSets, nil
}

func (ipt *IPTables) processIngressRules(policy NetworkPolicyInfo,
	targetDestPodIpSetName string, activePolicyIpSets map[string]bool, version string) error {

	// From network policy spec: "If field 'Ingress' is empty then this NetworkPolicy does not allow any traffic "
	// so no whitelist rules to be added to the network policy
	if policy.IngressRules == nil {
		return nil
	}

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return fmt.Errorf("Failed to initialize iptables executor due to: %s", err.Error())
	}

	policyChainName := networkPolicyChainName(policy.Namespace, policy.Name, version)

	// run through all the ingress rules in the spec and create iptables rules
	// in the chain for the network policy
	for i, ingressRule := range policy.IngressRules {

		if len(ingressRule.SrcPods) != 0 {
			srcPodIpSetName := policyIndexedSourcePodIpSetName(policy.Namespace, policy.Name, i)
			srcPodIpSet, err := ipt.ipSetHandler.Create(srcPodIpSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
			if err != nil {
				return fmt.Errorf("failed to create ipset: %s", err.Error())
			}

			activePolicyIpSets[srcPodIpSet.Name] = true

			ingressRuleSrcPodIps := make([]string, 0, len(ingressRule.SrcPods))
			for _, pod := range ingressRule.SrcPods {
				ingressRuleSrcPodIps = append(ingressRuleSrcPodIps, pod.IP)
			}
			err = srcPodIpSet.Refresh(ingressRuleSrcPodIps, utils.OptionTimeout, "0")
			if err != nil {
				glog.Errorf("failed to refresh srcPodIpSet: " + err.Error())
			}

			if len(ingressRule.Ports) != 0 {
				// case where 'ports' details and 'from' details specified in the ingress rule
				// so match on specified source and destination ip's and specified port (if any) and protocol
				for _, portProtocol := range ingressRule.Ports {
					comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
						policy.Name + " namespace " + policy.Namespace
					if err := ipt.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, srcPodIpSetName, targetDestPodIpSetName, portProtocol.Protocol, portProtocol.Port); err != nil {
						return err
					}
				}
			}

			if len(ingressRule.NamedPorts) != 0 {
				for j, endPoints := range ingressRule.NamedPorts {
					namedPortIpSetName := policyIndexedIngressNamedPortIpSetName(policy.Namespace, policy.Name, i, j)
					namedPortIpSet, err := ipt.ipSetHandler.Create(namedPortIpSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
					if err != nil {
						return fmt.Errorf("failed to create ipset: %s", err.Error())
					}
					activePolicyIpSets[namedPortIpSet.Name] = true
					err = namedPortIpSet.Refresh(endPoints.ips, utils.OptionTimeout, "0")
					if err != nil {
						glog.Errorf("failed to refresh namedPortIpSet: " + err.Error())
					}
					comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
						policy.Name + " namespace " + policy.Namespace
					if err := ipt.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, srcPodIpSetName, namedPortIpSetName, endPoints.Protocol, endPoints.Port); err != nil {
						return err
					}
				}
			}

			if len(ingressRule.Ports) == 0 && len(ingressRule.NamedPorts) == 0 {
				// case where no 'ports' details specified in the ingress rule but 'from' details specified
				// so match on specified source and destination ip with all port and protocol
				comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
					policy.Name + " namespace " + policy.Namespace
				if err := ipt.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, srcPodIpSetName, targetDestPodIpSetName, "", ""); err != nil {
					return err
				}
			}
		}

		// case where only 'ports' details specified but no 'from' details in the ingress rule
		// so match on all sources, with specified port (if any) and protocol
		if ingressRule.MatchAllSource && !ingressRule.MatchAllPorts {
			for _, portProtocol := range ingressRule.Ports {
				comment := "rule to ACCEPT traffic from all sources to dest pods selected by policy name: " +
					policy.Name + " namespace " + policy.Namespace
				if err := ipt.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, "", targetDestPodIpSetName, portProtocol.Protocol, portProtocol.Port); err != nil {
					return err
				}
			}

			for j, endPoints := range ingressRule.NamedPorts {
				namedPortIpSetName := policyIndexedIngressNamedPortIpSetName(policy.Namespace, policy.Name, i, j)
				namedPortIpSet, err := ipt.ipSetHandler.Create(namedPortIpSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
				if err != nil {
					return fmt.Errorf("failed to create ipset: %s", err.Error())
				}

				activePolicyIpSets[namedPortIpSet.Name] = true

				err = namedPortIpSet.Refresh(endPoints.ips, utils.OptionTimeout, "0")
				if err != nil {
					glog.Errorf("failed to refresh namedPortIpSet: " + err.Error())
				}
				comment := "rule to ACCEPT traffic from all sources to dest pods selected by policy name: " +
					policy.Name + " namespace " + policy.Namespace
				if err := ipt.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, "", namedPortIpSetName, endPoints.Protocol, endPoints.Port); err != nil {
					return err
				}
			}
		}

		// case where nether ports nor from details are speified in the ingress rule
		// so match on all ports, protocol, source IP's
		if ingressRule.MatchAllSource && ingressRule.MatchAllPorts {
			comment := "rule to ACCEPT traffic from all sources to dest pods selected by policy name: " +
				policy.Name + " namespace " + policy.Namespace
			if err := ipt.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, "", targetDestPodIpSetName, "", ""); err != nil {
				return err
			}
		}

		if len(ingressRule.SrcIPBlocks) != 0 {
			srcIpBlockIpSetName := policyIndexedSourceIpBlockIpSetName(policy.Namespace, policy.Name, i)
			srcIpBlockIpSet, err := ipt.ipSetHandler.Create(srcIpBlockIpSetName, utils.TypeHashNet, utils.OptionTimeout, "0")
			if err != nil {
				return fmt.Errorf("failed to create ipset: %s", err.Error())
			}
			activePolicyIpSets[srcIpBlockIpSet.Name] = true
			err = srcIpBlockIpSet.RefreshWithBuiltinOptions(translateIpBlocks(ingressRule.SrcIPBlocks))
			if err != nil {
				glog.Errorf("failed to refresh srcIpBlockIpSet: " + err.Error())
			}
			if !ingressRule.MatchAllPorts {
				for _, portProtocol := range ingressRule.Ports {
					comment := "rule to ACCEPT traffic from specified ipBlocks to dest pods selected by policy name: " +
						policy.Name + " namespace " + policy.Namespace
					if err := ipt.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, srcIpBlockIpSetName, targetDestPodIpSetName, portProtocol.Protocol, portProtocol.Port); err != nil {
						return err
					}
				}

				for j, endPoints := range ingressRule.NamedPorts {
					namedPortIpSetName := policyIndexedIngressNamedPortIpSetName(policy.Namespace, policy.Name, i, j)
					namedPortIpSet, err := ipt.ipSetHandler.Create(namedPortIpSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
					if err != nil {
						return fmt.Errorf("failed to create ipset: %s", err.Error())
					}

					activePolicyIpSets[namedPortIpSet.Name] = true

					err = namedPortIpSet.Refresh(endPoints.ips, utils.OptionTimeout, "0")
					if err != nil {
						glog.Errorf("failed to refresh namedPortIpSet: " + err.Error())
					}
					comment := "rule to ACCEPT traffic from specified ipBlocks to dest pods selected by policy name: " +
						policy.Name + " namespace " + policy.Namespace
					if err := ipt.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, srcIpBlockIpSetName, namedPortIpSetName, endPoints.Protocol, endPoints.Port); err != nil {
						return err
					}
				}
			}
			if ingressRule.MatchAllPorts {
				comment := "rule to ACCEPT traffic from specified ipBlocks to dest pods selected by policy name: " +
					policy.Name + " namespace " + policy.Namespace
				if err := ipt.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, srcIpBlockIpSetName, targetDestPodIpSetName, "", ""); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (ipt *IPTables) processEgressRules(policy NetworkPolicyInfo,
	targetSourcePodIpSetName string, activePolicyIpSets map[string]bool, version string) error {

	// From network policy spec: "If field 'Ingress' is empty then this NetworkPolicy does not allow any traffic "
	// so no whitelist rules to be added to the network policy
	if policy.EgressRules == nil {
		return nil
	}

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return fmt.Errorf("Failed to initialize iptables executor due to: %s", err.Error())
	}

	policyChainName := networkPolicyChainName(policy.Namespace, policy.Name, version)

	// run through all the egress rules in the spec and create iptables rules
	// in the chain for the network policy
	for i, egressRule := range policy.EgressRules {

		if len(egressRule.DstPods) != 0 {
			dstPodIpSetName := policyIndexedDestinationPodIpSetName(policy.Namespace, policy.Name, i)
			dstPodIpSet, err := ipt.ipSetHandler.Create(dstPodIpSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
			if err != nil {
				return fmt.Errorf("failed to create ipset: %s", err.Error())
			}

			activePolicyIpSets[dstPodIpSet.Name] = true

			egressRuleDstPodIps := make([]string, 0, len(egressRule.DstPods))
			for _, pod := range egressRule.DstPods {
				egressRuleDstPodIps = append(egressRuleDstPodIps, pod.IP)
			}
			err = dstPodIpSet.Refresh(egressRuleDstPodIps, utils.OptionTimeout, "0")
			if err != nil {
				glog.Errorf("failed to refresh dstPodIpSet: " + err.Error())
			}
			if len(egressRule.Ports) != 0 {
				// case where 'ports' details and 'from' details specified in the egress rule
				// so match on specified source and destination ip's and specified port (if any) and protocol
				for _, portProtocol := range egressRule.Ports {
					comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
						policy.Name + " namespace " + policy.Namespace
					if err := ipt.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, targetSourcePodIpSetName, dstPodIpSetName, portProtocol.Protocol, portProtocol.Port); err != nil {
						return err
					}
				}
			}

			if len(egressRule.NamedPorts) != 0 {
				for j, endPoints := range egressRule.NamedPorts {
					namedPortIpSetName := policyIndexedEgressNamedPortIpSetName(policy.Namespace, policy.Name, i, j)
					namedPortIpSet, err := ipt.ipSetHandler.Create(namedPortIpSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
					if err != nil {
						return fmt.Errorf("failed to create ipset: %s", err.Error())
					}

					activePolicyIpSets[namedPortIpSet.Name] = true

					err = namedPortIpSet.Refresh(endPoints.ips, utils.OptionTimeout, "0")
					if err != nil {
						glog.Errorf("failed to refresh namedPortIpSet: " + err.Error())
					}
					comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
						policy.Name + " namespace " + policy.Namespace
					if err := ipt.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, targetSourcePodIpSetName, namedPortIpSetName, endPoints.Protocol, endPoints.Port); err != nil {
						return err
					}
				}

			}

			if len(egressRule.Ports) == 0 && len(egressRule.NamedPorts) == 0 {
				// case where no 'ports' details specified in the ingress rule but 'from' details specified
				// so match on specified source and destination ip with all port and protocol
				comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
					policy.Name + " namespace " + policy.Namespace
				if err := ipt.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, targetSourcePodIpSetName, dstPodIpSetName, "", ""); err != nil {
					return err
				}
			}
		}

		// case where only 'ports' details specified but no 'to' details in the egress rule
		// so match on all sources, with specified port (if any) and protocol
		if egressRule.MatchAllDestinations && !egressRule.MatchAllPorts {
			for _, portProtocol := range egressRule.Ports {
				comment := "rule to ACCEPT traffic from source pods to all destinations selected by policy name: " +
					policy.Name + " namespace " + policy.Namespace
				if err := ipt.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, targetSourcePodIpSetName, "", portProtocol.Protocol, portProtocol.Port); err != nil {
					return err
				}
			}
		}

		// case where nether ports nor from details are speified in the egress rule
		// so match on all ports, protocol, source IP's
		if egressRule.MatchAllDestinations && egressRule.MatchAllPorts {
			comment := "rule to ACCEPT traffic from source pods to all destinations selected by policy name: " +
				policy.Name + " namespace " + policy.Namespace
			args := []string{"-m", "comment", "--comment", comment,
				"-m", "set", "--set", targetSourcePodIpSetName, "src",
				"-j", "ACCEPT"}
			err := iptablesCmdHandler.AppendUnique("filter", policyChainName, args...)
			if err != nil {
				return fmt.Errorf("Failed to run iptables command: %s", err.Error())
			}
		}
		if len(egressRule.DstIPBlocks) != 0 {
			dstIpBlockIpSetName := policyIndexedDestinationIpBlockIpSetName(policy.Namespace, policy.Name, i)
			dstIpBlockIpSet, err := ipt.ipSetHandler.Create(dstIpBlockIpSetName, utils.TypeHashNet, utils.OptionTimeout, "0")
			if err != nil {
				return fmt.Errorf("failed to create ipset: %s", err.Error())
			}
			activePolicyIpSets[dstIpBlockIpSet.Name] = true
			err = dstIpBlockIpSet.RefreshWithBuiltinOptions(translateIpBlocks(egressRule.DstIPBlocks))
			if err != nil {
				glog.Errorf("failed to refresh dstIpBlockIpSet: " + err.Error())
			}
			if !egressRule.MatchAllPorts {
				for _, portProtocol := range egressRule.Ports {
					comment := "rule to ACCEPT traffic from source pods to specified ipBlocks selected by policy name: " +
						policy.Name + " namespace " + policy.Namespace
					args := []string{"-m", "comment", "--comment", comment,
						"-m", "set", "--set", targetSourcePodIpSetName, "src",
						"-m", "set", "--set", dstIpBlockIpSetName, "dst",
						"-p", portProtocol.Protocol}

					if portProtocol.Port != "" {
						args = append(args, "--dport", portProtocol.Port)
					}

					args = append(args, "-j", "ACCEPT")

					err := iptablesCmdHandler.AppendUnique("filter", policyChainName, args...)
					if err != nil {
						return fmt.Errorf("Failed to run iptables command: %s", err.Error())
					}
				}
			}
			if egressRule.MatchAllPorts {
				comment := "rule to ACCEPT traffic from source pods to specified ipBlocks selected by policy name: " +
					policy.Name + " namespace " + policy.Namespace
				args := []string{"-m", "comment", "--comment", comment,
					"-m", "set", "--set", targetSourcePodIpSetName, "src",
					"-m", "set", "--set", dstIpBlockIpSetName, "dst",
					"-j", "ACCEPT"}
				err := iptablesCmdHandler.AppendUnique("filter", policyChainName, args...)
				if err != nil {
					return fmt.Errorf("Failed to run iptables command: %s", err.Error())
				}
			}
		}
	}
	return nil
}

func (ipt *IPTables) appendRuleToPolicyChain(iptablesCmdHandler *iptables.IPTables, policyChainName, comment, srcIpSetName, dstIpSetName, protocol, dPort string) error {
	if iptablesCmdHandler == nil {
		return fmt.Errorf("Failed to run iptables command: iptablesCmdHandler is nil")
	}
	args := make([]string, 0)
	if comment != "" {
		args = append(args, "-m", "comment", "--comment", comment)
	}
	if srcIpSetName != "" {
		args = append(args, "-m", "set", "--set", srcIpSetName, "src")
	}
	if dstIpSetName != "" {
		args = append(args, "-m", "set", "--set", dstIpSetName, "dst")
	}
	if protocol != "" {
		args = append(args, "-p", protocol)
	}
	if dPort != "" {
		args = append(args, "--dport", dPort)
	}
	args = append(args, "-j", "ACCEPT")
	err := iptablesCmdHandler.AppendUnique("filter", policyChainName, args...)
	if err != nil {
		return fmt.Errorf("Failed to run iptables command: %s", err.Error())
	}
	return nil
}

func (ipt *IPTables) syncPodFirewallChains(version string, networkPoliciesInfo *[]NetworkPolicyInfo, ingressNetworkPolicyEnabledPods, egressNetworkPolicyEnabledPods *map[string]PodInfo) (map[string]bool, error) {

	activePodFwChains := make(map[string]bool)

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		glog.Fatalf("Failed to initialize iptables executor: %s", err.Error())
	}

	// loop through the pods running on the node which to which ingress network policies to be applied
	if err != nil {
		return nil, err
	}
	for _, pod := range *ingressNetworkPolicyEnabledPods {

		// below condition occurs when we get trasient update while removing or adding pod
		// subseqent update will do the correct action
		if len(pod.IP) == 0 || pod.IP == "" {
			continue
		}

		// ensure pod specific firewall chain exist for all the pods that need ingress firewall
		podFwChainName := podFirewallChainName(pod.Namespace, pod.Name, version)
		err = iptablesCmdHandler.NewChain("filter", podFwChainName)
		if err != nil && err.(*iptables.Error).ExitStatus() != 1 {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		activePodFwChains[podFwChainName] = true

		// add entries in pod firewall to run through required network policies
		for _, policy := range *networkPoliciesInfo {
			if _, ok := policy.TargetPods[pod.IP]; ok {
				comment := "run through nw policy " + policy.Name
				policyChainName := networkPolicyChainName(policy.Namespace, policy.Name, version)
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

		comment := "rule to permit the traffic traffic to pods when source is the pod's local node"
		args := []string{"-m", "comment", "--comment", comment, "-m", "addrtype", "--src-type", "LOCAL", "-d", pod.IP, "-j", "ACCEPT"}
		exists, err := iptablesCmdHandler.Exists("filter", podFwChainName, args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err := iptablesCmdHandler.Insert("filter", podFwChainName, 1, args...)
			if err != nil {
				return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
			}
		}

		// ensure stateful firewall, that permits return traffic for the traffic originated by the pod
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

		// ensure there is rule in filter table and FORWARD chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting routed (coming for other node pods)
		comment = "rule to jump traffic destined to POD name:" + pod.Name + " namespace: " + pod.Namespace +
			" to chain " + podFwChainName
		args = []string{"-m", "comment", "--comment", comment, "-d", pod.IP, "-j", podFwChainName}
		exists, err = iptablesCmdHandler.Exists("filter", "FORWARD", args...)
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
		comment = "rule to jump traffic destined to POD name:" + pod.Name + " namespace: " + pod.Namespace +
			" to chain " + podFwChainName
		args = []string{"-m", "physdev", "--physdev-is-bridged",
			"-m", "comment", "--comment", comment,
			"-d", pod.IP,
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
		comment = "default rule to REJECT traffic destined for POD name:" + pod.Name + " namespace: " + pod.Namespace
		args = []string{"-m", "comment", "--comment", comment, "-j", "REJECT"}
		err = iptablesCmdHandler.AppendUnique("filter", podFwChainName, args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
	}

	// loop through the pods running on the node which egress network policies to be applied
	if err != nil {
		return nil, err
	}
	for _, pod := range *egressNetworkPolicyEnabledPods {

		// below condition occurs when we get trasient update while removing or adding pod
		// subseqent update will do the correct action
		if len(pod.IP) == 0 || pod.IP == "" {
			continue
		}

		// ensure pod specific firewall chain exist for all the pods that need egress firewall
		podFwChainName := podFirewallChainName(pod.Namespace, pod.Name, version)
		err = iptablesCmdHandler.NewChain("filter", podFwChainName)
		if err != nil && err.(*iptables.Error).ExitStatus() != 1 {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		activePodFwChains[podFwChainName] = true

		// add entries in pod firewall to run through required network policies
		for _, policy := range *networkPoliciesInfo {
			if _, ok := policy.TargetPods[pod.IP]; ok {
				comment := "run through nw policy " + policy.Name
				policyChainName := networkPolicyChainName(policy.Namespace, policy.Name, version)
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

		// ensure stateful firewall, that permits return traffic for the traffic originated by the pod
		comment := "rule for stateful firewall for pod"
		args := []string{"-m", "comment", "--comment", comment, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
		exists, err := iptablesCmdHandler.Exists("filter", podFwChainName, args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err := iptablesCmdHandler.Insert("filter", podFwChainName, 1, args...)
			if err != nil {
				return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
			}
		}

		// ensure there is rule in filter table and FORWARD chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting routed (coming for other node pods)
		comment = "rule to jump traffic from POD name:" + pod.Name + " namespace: " + pod.Namespace +
			" to chain " + podFwChainName
		args = []string{"-m", "comment", "--comment", comment, "-s", pod.IP, "-j", podFwChainName}
		exists, err = iptablesCmdHandler.Exists("filter", "FORWARD", args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err := iptablesCmdHandler.Insert("filter", "FORWARD", 1, args...)
			if err != nil {
				return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
			}
		}

		// ensure there is rule in filter table and forward chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting switched (coming for same node pods)
		comment = "rule to jump traffic from POD name:" + pod.Name + " namespace: " + pod.Namespace +
			" to chain " + podFwChainName
		args = []string{"-m", "physdev", "--physdev-is-bridged",
			"-m", "comment", "--comment", comment,
			"-s", pod.IP,
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
		comment = "default rule to REJECT traffic destined for POD name:" + pod.Name + " namespace: " + pod.Namespace
		args = []string{"-m", "comment", "--comment", comment, "-j", "REJECT"}
		err = iptablesCmdHandler.AppendUnique("filter", podFwChainName, args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
	}

	return activePodFwChains, nil
}

func cleanupStaleRules(activePolicyChains, activePodFwChains, activePolicyIPSets map[string]bool) error {

	cleanupPodFwChains := make([]string, 0)
	cleanupPolicyChains := make([]string, 0)
	cleanupPolicyIPSets := make([]*utils.Set, 0)

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		glog.Fatalf("failed to initialize iptables command executor due to %s", err.Error())
	}
	ipsets, err := utils.NewIPSet(false)
	if err != nil {
		glog.Fatalf("failed to create ipsets command executor due to %s", err.Error())
	}
	err = ipsets.Save()
	if err != nil {
		glog.Fatalf("failed to initialize ipsets command executor due to %s", err.Error())
	}

	// get the list of chains created for pod firewall and network policies
	chains, err := iptablesCmdHandler.ListChains("filter")
	for _, chain := range chains {
		if strings.HasPrefix(chain, kubeNetworkPolicyChainPrefix) {
			if _, ok := activePolicyChains[chain]; !ok {
				cleanupPolicyChains = append(cleanupPolicyChains, chain)
			}
		}
		if strings.HasPrefix(chain, kubePodFirewallChainPrefix) {
			if _, ok := activePodFwChains[chain]; !ok {
				cleanupPodFwChains = append(cleanupPodFwChains, chain)
			}
		}
	}
	for _, set := range ipsets.Sets {
		if strings.HasPrefix(set.Name, kubeSourceIpSetPrefix) ||
			strings.HasPrefix(set.Name, kubeDestinationIpSetPrefix) {
			if _, ok := activePolicyIPSets[set.Name]; !ok {
				cleanupPolicyIPSets = append(cleanupPolicyIPSets, set)
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
		var realRuleNo int
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
		glog.V(2).Infof("Found pod fw chain to cleanup: %s", chain)
		err = iptablesCmdHandler.ClearChain("filter", chain)
		if err != nil {
			return fmt.Errorf("Failed to flush the rules in chain %s due to %s", chain, err.Error())
		}
		err = iptablesCmdHandler.DeleteChain("filter", chain)
		if err != nil {
			return fmt.Errorf("Failed to delete the chain %s due to %s", chain, err.Error())
		}
		glog.V(2).Infof("Deleted pod specific firewall chain: %s from the filter table", chain)
	}

	// cleanup network policy chains
	for _, policyChain := range cleanupPolicyChains {
		glog.V(2).Infof("Found policy chain to cleanup %s", policyChain)

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
		glog.V(2).Infof("Deleted network policy chain: %s from the filter table", policyChain)
	}

	// cleanup network policy ipsets
	for _, set := range cleanupPolicyIPSets {
		err = set.Destroy()
		if err != nil {
			return fmt.Errorf("Failed to delete ipset %s due to %s", set.Name, err)
		}
	}
	return nil
}

func podFirewallChainName(namespace, podName string, version string) string {
	hash := sha256.Sum256([]byte(namespace + podName + version))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubePodFirewallChainPrefix + encoded[:16]
}

func networkPolicyChainName(namespace, policyName string, version string) string {
	hash := sha256.Sum256([]byte(namespace + policyName + version))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeNetworkPolicyChainPrefix + encoded[:16]
}

func policySourcePodIpSetName(namespace, policyName string) string {
	hash := sha256.Sum256([]byte(namespace + policyName))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeSourceIpSetPrefix + encoded[:16]
}

func policyDestinationPodIpSetName(namespace, policyName string) string {
	hash := sha256.Sum256([]byte(namespace + policyName))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIpSetPrefix + encoded[:16]
}

func policyIndexedSourcePodIpSetName(namespace, policyName string, ingressRuleNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) + "pod"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeSourceIpSetPrefix + encoded[:16]
}

func policyIndexedDestinationPodIpSetName(namespace, policyName string, egressRuleNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) + "pod"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIpSetPrefix + encoded[:16]
}

func policyIndexedSourceIpBlockIpSetName(namespace, policyName string, ingressRuleNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) + "ipblock"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeSourceIpSetPrefix + encoded[:16]
}

func policyIndexedDestinationIpBlockIpSetName(namespace, policyName string, egressRuleNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) + "ipblock"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIpSetPrefix + encoded[:16]
}

func policyIndexedIngressNamedPortIpSetName(namespace, policyName string, ingressRuleNo, namedPortNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) + strconv.Itoa(namedPortNo) + "namedport"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIpSetPrefix + encoded[:16]
}

func policyIndexedEgressNamedPortIpSetName(namespace, policyName string, egressRuleNo, namedPortNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) + strconv.Itoa(namedPortNo) + "namedport"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIpSetPrefix + encoded[:16]
}

func (ipt *IPTables) Shutdown() {
	//no op
}

// Cleanup cleanup configurations done
func (ipt *IPTables) Cleanup() {

	glog.Info("Cleaning up iptables configuration permanently done by kube-router")

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		glog.Errorf("Failed to initialize iptables executor: %s", err.Error())
	}

	// delete jump rules in FORWARD chain to pod specific firewall chain
	forwardChainRules, err := iptablesCmdHandler.List("filter", "FORWARD")
	if err != nil {
		glog.Errorf("Failed to delete iptables rules as part of cleanup")
		return
	}

	// TODO: need a better way to delte rule with out using number
	var realRuleNo int
	for i, rule := range forwardChainRules {
		if strings.Contains(rule, kubePodFirewallChainPrefix) {
			err = iptablesCmdHandler.Delete("filter", "FORWARD", strconv.Itoa(i-realRuleNo))
			realRuleNo++
		}
	}

	// delete jump rules in OUTPUT chain to pod specific firewall chain
	forwardChainRules, err = iptablesCmdHandler.List("filter", "OUTPUT")
	if err != nil {
		glog.Errorf("Failed to delete iptables rules as part of cleanup")
		return
	}

	// TODO: need a better way to delte rule with out using number
	realRuleNo = 0
	for i, rule := range forwardChainRules {
		if strings.Contains(rule, kubePodFirewallChainPrefix) {
			err = iptablesCmdHandler.Delete("filter", "OUTPUT", strconv.Itoa(i-realRuleNo))
			realRuleNo++
		}
	}

	// flush and delete pod specific firewall chain
	chains, err := iptablesCmdHandler.ListChains("filter")
	for _, chain := range chains {
		if strings.HasPrefix(chain, kubePodFirewallChainPrefix) {
			err = iptablesCmdHandler.ClearChain("filter", chain)
			if err != nil {
				glog.Errorf("Failed to cleanup iptables rules: " + err.Error())
				return
			}
			err = iptablesCmdHandler.DeleteChain("filter", chain)
			if err != nil {
				glog.Errorf("Failed to cleanup iptables rules: " + err.Error())
				return
			}
		}
	}

	// flush and delete per network policy specific chain
	chains, err = iptablesCmdHandler.ListChains("filter")
	for _, chain := range chains {
		if strings.HasPrefix(chain, kubeNetworkPolicyChainPrefix) {
			err = iptablesCmdHandler.ClearChain("filter", chain)
			if err != nil {
				glog.Errorf("Failed to cleanup iptables rules: " + err.Error())
				return
			}
			err = iptablesCmdHandler.DeleteChain("filter", chain)
			if err != nil {
				glog.Errorf("Failed to cleanup iptables rules: " + err.Error())
				return
			}
		}
	}

	// delete all ipsets
	ipset, err := utils.NewIPSet(false)
	if err != nil {
		glog.Errorf("Failed to clean up ipsets: " + err.Error())
	}
	err = ipset.Save()
	if err != nil {
		glog.Errorf("Failed to clean up ipsets: " + err.Error())
	}
	err = ipset.DestroyAllWithin()
	if err != nil {
		glog.Errorf("Failed to clean up ipsets: " + err.Error())
	}
	glog.Infof("Successfully cleaned the iptables configuration done by kube-router")
}

func translateIpBlocks(input []*v1.IPBlock) [][]string {
	ipBlocks := make([][]string, 0)
	for _, b := range input {
		if cidr := b.CIDR; strings.HasSuffix(cidr, "/0") {
			ipBlocks = append(ipBlocks, []string{"0.0.0.0/1", utils.OptionTimeout, "0"}, []string{"128.0.0.0/1", utils.OptionTimeout, "0"})
		} else {
			ipBlocks = append(ipBlocks, []string{cidr, utils.OptionTimeout, "0"})
		}
		for _, except := range b.Except {
			if strings.HasSuffix(except, "/0") {
				ipBlocks = append(ipBlocks, []string{"0.0.0.0/1", utils.OptionTimeout, "0", utils.OptionNoMatch}, []string{"128.0.0.0/1", utils.OptionTimeout, "0", utils.OptionNoMatch})
			} else {
				ipBlocks = append(ipBlocks, []string{except, utils.OptionTimeout, "0", utils.OptionNoMatch})
			}
		}
	}
	return ipBlocks
}

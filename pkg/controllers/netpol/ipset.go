package netpol

import (
	"fmt"
	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/golang/glog"
	"strings"
	"time"
)

// RequestIpsetsSync allows the request of a full ipsets sync without blocking the callee
func (npc *NetworkPolicyController) RequestIpsetsSync() {
	select {
	case npc.ipsetsSyncRequestChan <- struct{}{}:
		glog.V(3).Info("Ipsets sync request queue was empty so a ipsets sync request was successfully sent")
	default: // Don't block if the buffered channel is full, return quickly so that we don't block callee execution
		glog.V(1).Info("Ipsets sync request queue was full, skipping...")
	}
}

func (npc *NetworkPolicyController) fullIpsetsSync() {
	var err error
	var networkPoliciesInfo []networkPolicyInfo
	npc.mu.Lock()
	defer npc.mu.Unlock()

	healthcheck.SendHeartBeat(npc.healthChan, "NPC")

	if npc.v1NetworkPolicy {
		networkPoliciesInfo, err = npc.buildNetworkPoliciesInfo()
		if err != nil {
			glog.Errorf("Aborting sync. Failed to build network policies: %v", err.Error())
			return
		}
	} else {
		// TODO remove the Beta support
		networkPoliciesInfo, err = npc.buildBetaNetworkPoliciesInfo()
		if err != nil {
			glog.Errorf("Aborting sync. Failed to build network policies: %v", err.Error())
			return
		}
	}

	_, err = npc.syncNetworkPolicyIpSets(networkPoliciesInfo)
	if err != nil {
		glog.Errorf("Aborting sync. Failed to sync network policy ipsets: %v" + err.Error())
		return
	}
}

// All pod's matched by network policy spec podselector labels are grouped together
// in one ipset which is used for matching destination ip address.
func (npc *NetworkPolicyController) syncNetworkPolicyIpSets(networkPoliciesInfo []networkPolicyInfo) (map[string]bool, error) {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		metrics.ControllerIpSetSyncTime.Observe(endTime.Seconds())
		glog.V(2).Infof("Syncing network policy ipsets took %v", endTime)
	}()

	activePolicyIpSets := make(map[string]bool)

	// run through all network policies
	for _, policy := range networkPoliciesInfo {
		currnetPodIps := make([]string, 0, len(policy.targetPods))
		for ip := range policy.targetPods {
			currnetPodIps = append(currnetPodIps, ip)
		}

		if policy.policyType == "both" || policy.policyType == "ingress" {
			// create a ipset for all destination pod ip's matched by the policy spec PodSelector
			targetDestPodIpSetName := policyDestinationPodIpSetName(policy.namespace, policy.name)
			targetDestPodIpSet, err := npc.ipSetHandler.Create(targetDestPodIpSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
			if err != nil {
				return nil, fmt.Errorf("failed to create ipset: %s", err.Error())
			}
			err = targetDestPodIpSet.Refresh(currnetPodIps, utils.OptionTimeout, "0")
			if err != nil {
				glog.Errorf("failed to refresh targetDestPodIpSet,: " + err.Error())
			}
			activePolicyIpSets[targetDestPodIpSet.Name] = true
		}

		if policy.policyType == "both" || policy.policyType == "egress" {
			// create a ipset for all source pod ip's matched by the policy spec PodSelector
			targetSourcePodIpSetName := policySourcePodIpSetName(policy.namespace, policy.name)
			targetSourcePodIpSet, err := npc.ipSetHandler.Create(targetSourcePodIpSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
			if err != nil {
				return nil, fmt.Errorf("failed to create ipset: %s", err.Error())
			}
			err = targetSourcePodIpSet.Refresh(currnetPodIps, utils.OptionTimeout, "0")
			if err != nil {
				glog.Errorf("failed to refresh targetSourcePodIpSet: " + err.Error())
			}
			activePolicyIpSets[targetSourcePodIpSet.Name] = true
		}

		// run through all the ingress rules in the spec and create iptables rules
		// in the chain for the network policy
		for i, ingressRule := range policy.ingressRules {
			if len(ingressRule.srcPods) != 0 {
				srcPodIpSetName := policyIndexedSourcePodIpSetName(policy.namespace, policy.name, i)
				srcPodIpSet, err := npc.ipSetHandler.Create(srcPodIpSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
				if err != nil {
					return nil, fmt.Errorf("failed to create ipset: %s", err.Error())
				}

				activePolicyIpSets[srcPodIpSet.Name] = true

				ingressRuleSrcPodIps := make([]string, 0, len(ingressRule.srcPods))
				for _, pod := range ingressRule.srcPods {
					ingressRuleSrcPodIps = append(ingressRuleSrcPodIps, pod.ip)
				}
				err = srcPodIpSet.Refresh(ingressRuleSrcPodIps, utils.OptionTimeout, "0")
				if err != nil {
					glog.Errorf("failed to refresh srcPodIpSet: " + err.Error())
				}

				if len(ingressRule.namedPorts) != 0 {
					for j, endPoints := range ingressRule.namedPorts {
						namedPortIpSetName := policyIndexedIngressNamedPortIpSetName(policy.namespace, policy.name, i, j)
						namedPortIpSet, err := npc.ipSetHandler.Create(namedPortIpSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
						if err != nil {
							return nil, fmt.Errorf("failed to create ipset: %s", err.Error())
						}
						activePolicyIpSets[namedPortIpSet.Name] = true
						err = namedPortIpSet.Refresh(endPoints.ips, utils.OptionTimeout, "0")
						if err != nil {
							glog.Errorf("failed to refresh namedPortIpSet: " + err.Error())
						}
					}
				}
			}
		}

		// run through all the egress rules in the spec and create iptables rules
		// in the chain for the network policy
		for i, egressRule := range policy.egressRules {
			if len(egressRule.dstPods) != 0 {
				dstPodIpSetName := policyIndexedDestinationPodIpSetName(policy.namespace, policy.name, i)
				dstPodIpSet, err := npc.ipSetHandler.Create(dstPodIpSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
				if err != nil {
					return nil, fmt.Errorf("failed to create ipset: %s", err.Error())
				}

				activePolicyIpSets[dstPodIpSet.Name] = true

				egressRuleDstPodIps := make([]string, 0, len(egressRule.dstPods))
				for _, pod := range egressRule.dstPods {
					egressRuleDstPodIps = append(egressRuleDstPodIps, pod.ip)
				}
				err = dstPodIpSet.Refresh(egressRuleDstPodIps, utils.OptionTimeout, "0")
				if err != nil {
					glog.Errorf("failed to refresh dstPodIpSet: " + err.Error())
				}

				if len(egressRule.namedPorts) != 0 {
					for j, endPoints := range egressRule.namedPorts {
						namedPortIpSetName := policyIndexedEgressNamedPortIpSetName(policy.namespace, policy.name, i, j)
						namedPortIpSet, err := npc.ipSetHandler.Create(namedPortIpSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
						if err != nil {
							return nil, fmt.Errorf("failed to create ipset: %s", err.Error())
						}

						activePolicyIpSets[namedPortIpSet.Name] = true

						err = namedPortIpSet.Refresh(endPoints.ips, utils.OptionTimeout, "0")
						if err != nil {
							glog.Errorf("failed to refresh namedPortIpSet: " + err.Error())
						}
					}
				}
			}

			if len(egressRule.dstIPBlocks) != 0 {
				dstIpBlockIpSetName := policyIndexedDestinationIpBlockIpSetName(policy.namespace, policy.name, i)
				dstIpBlockIpSet, err := npc.ipSetHandler.Create(dstIpBlockIpSetName, utils.TypeHashNet, utils.OptionTimeout, "0")
				if err != nil {
					return nil, fmt.Errorf("failed to create ipset: %s", err.Error())
				}
				activePolicyIpSets[dstIpBlockIpSet.Name] = true
				err = dstIpBlockIpSet.RefreshWithBuiltinOptions(egressRule.dstIPBlocks)
				if err != nil {
					glog.Errorf("failed to refresh dstIpBlockIpSet: " + err.Error())
				}
			}
		}
	}

	glog.V(2).Infof("Ipsets are synchronized with the network policies.")

	return activePolicyIpSets, nil
}

func cleanupStaleIpSets(activePolicyIPSets map[string]bool) error {
	cleanupPolicyIPSets := make([]*utils.Set, 0)

	ipsets, err := utils.NewIPSet(false)
	if err != nil {
		glog.Fatalf("failed to create ipsets command executor due to %s", err.Error())
	}
	err = ipsets.Save()
	if err != nil {
		glog.Fatalf("failed to initialize ipsets command executor due to %s", err.Error())
	}

	for _, set := range ipsets.Sets {
		if strings.HasPrefix(set.Name, kubeSourceIpSetPrefix) ||
			strings.HasPrefix(set.Name, kubeDestinationIpSetPrefix) {
			if _, ok := activePolicyIPSets[set.Name]; !ok {
				cleanupPolicyIPSets = append(cleanupPolicyIPSets, set)
			}
		}
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

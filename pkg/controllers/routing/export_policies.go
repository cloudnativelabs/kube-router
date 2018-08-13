package routing

import (
	"errors"
	"fmt"

	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/table"
	v1core "k8s.io/api/core/v1"
)

// BGP export policies are added so that following conditions are met
//
// - by default export of all routes from the RIB to the neighbour's is denied, and explicity statements are added i
//   to permit the desired routes to be exported
// - each node is allowed to advertise its assigned pod CIDR's to all of its iBGP peer neighbours with same ASN if --enable-ibgp=true
// - each node is allowed to advertise its assigned pod CIDR's to all of its external BGP peer neighbours
//   only if --advertise-pod-cidr flag is set to true
// - each node is NOT allowed to advertise its assigned pod CIDR's to all of its external BGP peer neighbours
//   only if --advertise-pod-cidr flag is set to false
// - each node is allowed to advertise service VIP's (cluster ip, load balancer ip, external IP) ONLY to external
//   BGP peers
// - each node is NOT allowed to advertise service VIP's (cluster ip, load balancer ip, external IP) to
//   iBGP peers
// - an option to allow overriding the next-hop-address with the outgoing ip for external bgp peers
func (nrc *NetworkRoutingController) addExportPolicies() error {

	// we are rr server do not add export policies
	if nrc.bgpRRServer {
		return nil
	}

	cidr, err := utils.GetPodCidrFromNodeSpec(nrc.clientset, nrc.hostnameOverride)
	if err != nil {
		return err
	}

	// creates prefix set to represent the assigned node's pod CIDR
	podCidrPrefixSet, err := table.NewPrefixSet(config.PrefixSet{
		PrefixSetName: "podcidrprefixset",
		PrefixList: []config.Prefix{
			{
				IpPrefix: cidr,
			},
		},
	})
	err = nrc.bgpServer.ReplaceDefinedSet(podCidrPrefixSet)
	if err != nil {
		nrc.bgpServer.AddDefinedSet(podCidrPrefixSet)
	}

	// creates prefix set to represent all the advertisable IP associated with the services
	advIpPrefixList := make([]config.Prefix, 0)
	advIps, _, _ := nrc.getAllVIPs()
	for _, ip := range advIps {
		advIpPrefixList = append(advIpPrefixList, config.Prefix{IpPrefix: ip + "/32"})
	}
	clusterIpPrefixSet, err := table.NewPrefixSet(config.PrefixSet{
		PrefixSetName: "clusteripprefixset",
		PrefixList:    advIpPrefixList,
	})
	err = nrc.bgpServer.ReplaceDefinedSet(clusterIpPrefixSet)
	if err != nil {
		nrc.bgpServer.AddDefinedSet(clusterIpPrefixSet)
	}

	statements := make([]config.Statement, 0)

	var bgpActions config.BgpActions
	if nrc.pathPrepend {
		bgpActions = config.BgpActions{
			SetAsPathPrepend: config.SetAsPathPrepend{
				As:      nrc.pathPrependAS,
				RepeatN: nrc.pathPrependCount,
			},
		}
	}

	if nrc.bgpEnableInternal {
		// Get the current list of the nodes from the local cache
		nodes := nrc.nodeLister.List()
		iBGPPeers := make([]string, 0)
		for _, node := range nodes {
			nodeObj := node.(*v1core.Node)
			nodeIP, err := utils.GetNodeIP(nodeObj)
			if err != nil {
				return fmt.Errorf("Failed to find a node IP: %s", err)
			}
			iBGPPeers = append(iBGPPeers, nodeIP.String())
		}
		iBGPPeerNS, _ := table.NewNeighborSet(config.NeighborSet{
			NeighborSetName:  "iBGPpeerset",
			NeighborInfoList: iBGPPeers,
		})
		err = nrc.bgpServer.ReplaceDefinedSet(iBGPPeerNS)
		if err != nil {
			nrc.bgpServer.AddDefinedSet(iBGPPeerNS)
		}
		actions := config.Actions{
			RouteDisposition: config.ROUTE_DISPOSITION_ACCEPT_ROUTE,
		}
		if nrc.overrideNextHop {
			actions.BgpActions.SetNextHop = "self"
		}
		// statement to represent the export policy to permit advertising node's pod CIDR
		statements = append(statements,
			config.Statement{
				Conditions: config.Conditions{
					MatchPrefixSet: config.MatchPrefixSet{
						PrefixSet: "podcidrprefixset",
					},
					MatchNeighborSet: config.MatchNeighborSet{
						NeighborSet: "iBGPpeerset",
					},
				},
				Actions: actions,
			})
	}

	externalBgpPeers := make([]string, 0)
	if len(nrc.globalPeerRouters) != 0 {
		for _, peer := range nrc.globalPeerRouters {
			externalBgpPeers = append(externalBgpPeers, peer.NeighborAddress)
		}
	}
	if len(nrc.nodePeerRouters) != 0 {
		for _, peer := range nrc.nodePeerRouters {
			externalBgpPeers = append(externalBgpPeers, peer)
		}
	}
	if len(externalBgpPeers) > 0 {
		ns, _ := table.NewNeighborSet(config.NeighborSet{
			NeighborSetName:  "externalpeerset",
			NeighborInfoList: externalBgpPeers,
		})
		err = nrc.bgpServer.ReplaceDefinedSet(ns)
		if err != nil {
			nrc.bgpServer.AddDefinedSet(ns)
		}
		if nrc.overrideNextHop {
			bgpActions.SetNextHop = "self"
		}
		// statement to represent the export policy to permit advertising cluster IP's
		// only to the global BGP peer or node specific BGP peer
		statements = append(statements, config.Statement{
			Conditions: config.Conditions{
				MatchPrefixSet: config.MatchPrefixSet{
					PrefixSet: "clusteripprefixset",
				},
				MatchNeighborSet: config.MatchNeighborSet{
					NeighborSet: "externalpeerset",
				},
			},
			Actions: config.Actions{
				RouteDisposition: config.ROUTE_DISPOSITION_ACCEPT_ROUTE,
				BgpActions:       bgpActions,
			},
		})
		if nrc.advertisePodCidr {
			actions := config.Actions{
				RouteDisposition: config.ROUTE_DISPOSITION_ACCEPT_ROUTE,
			}
			if nrc.overrideNextHop {
				actions.BgpActions.SetNextHop = "self"
			}
			statements = append(statements, config.Statement{
				Conditions: config.Conditions{
					MatchPrefixSet: config.MatchPrefixSet{
						PrefixSet: "podcidrprefixset",
					},
					MatchNeighborSet: config.MatchNeighborSet{
						NeighborSet: "externalpeerset",
					},
				},
				Actions: actions,
			})
		}
	}

	definition := config.PolicyDefinition{
		Name:       "kube_router",
		Statements: statements,
	}

	policy, err := table.NewPolicy(definition)
	if err != nil {
		return errors.New("Failed to create new policy: " + err.Error())
	}

	policyAlreadyExists := false
	policyList := nrc.bgpServer.GetPolicy()
	for _, existingPolicy := range policyList {
		if existingPolicy.Name == "kube_router" {
			policyAlreadyExists = true
		}
	}

	if !policyAlreadyExists {
		err = nrc.bgpServer.AddPolicy(policy, false)
		if err != nil {
			return errors.New("Failed to add policy: " + err.Error())
		}
	}

	policyAssignmentExists := false
	_, existingPolicyAssignments, err := nrc.bgpServer.GetPolicyAssignment("", table.POLICY_DIRECTION_EXPORT)
	if err == nil {
		for _, existingPolicyAssignment := range existingPolicyAssignments {
			if existingPolicyAssignment.Name == "kube_router" {
				policyAssignmentExists = true
			}
		}
	}

	if !policyAssignmentExists {
		err = nrc.bgpServer.AddPolicyAssignment("",
			table.POLICY_DIRECTION_EXPORT,
			[]*config.PolicyDefinition{&definition},
			table.ROUTE_TYPE_REJECT)
		if err != nil {
			return errors.New("Failed to add policy assignment: " + err.Error())
		}
	} else {
		// configure default BGP export policy to reject
		err = nrc.bgpServer.ReplacePolicyAssignment("",
			table.POLICY_DIRECTION_EXPORT,
			[]*config.PolicyDefinition{&definition},
			table.ROUTE_TYPE_REJECT)
		if err != nil {
			return errors.New("Failed to replace policy assignment: " + err.Error())
		}
	}

	return nil
}

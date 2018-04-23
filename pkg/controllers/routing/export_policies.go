package routing

import (
	"errors"
	"fmt"

	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/table"
	v1core "k8s.io/api/core/v1"
)

// Each node advertises its pod CIDR to the nodes with same ASN (iBGP peers) and to the global BGP peer
// or per node BGP peer. Each node ends up advertising not only pod CIDR assigned to the self but other
// learned routes to the node pod CIDR's as well to global BGP peer or per node BGP peers. external BGP
// peer will randomly (since all path have equal selection attributes) select the routes from multiple
// routes to a pod CIDR which will result in extra hop. To prevent this behaviour this methods add
// defult export policy to reject everything and an explicit policy is added so that each node only
// advertised the pod CIDR assigned to it. Additionally export policy is added so that each node
// advertises cluster IP's ONLY to the external BGP peers (and not to iBGP peers).
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

	// Get the current list of the nodes from the local cache
	nodes := nrc.nodeLister.List()
	iBgpPeers := make([]string, 0)
	for _, node := range nodes {
		nodeObj := node.(*v1core.Node)
		nodeIP, err := utils.GetNodeIP(nodeObj)
		if err != nil {
			return fmt.Errorf("Failed to find a node IP: %s", err)
		}
		iBgpPeers = append(iBgpPeers, nodeIP.String())
	}
	iBgpPeerNS, _ := table.NewNeighborSet(config.NeighborSet{
		NeighborSetName:  "ipbgppeerset",
		NeighborInfoList: iBgpPeers,
	})
	err = nrc.bgpServer.ReplaceDefinedSet(iBgpPeerNS)
	if err != nil {
		nrc.bgpServer.AddDefinedSet(iBgpPeerNS)
	}
	// statement to represent the export policy to permit advertising node's pod CIDR
	statements = append(statements,
		config.Statement{
			Conditions: config.Conditions{
				MatchPrefixSet: config.MatchPrefixSet{
					PrefixSet: "podcidrprefixset",
				},
				MatchNeighborSet: config.MatchNeighborSet{
					NeighborSet: "ipbgppeerset",
				},
			},
			Actions: config.Actions{
				RouteDisposition: config.ROUTE_DISPOSITION_ACCEPT_ROUTE,
			},
		})

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
			},
		})
		if nrc.advertiseNodePodCidr {
			statements = append(statements, config.Statement{
				Conditions: config.Conditions{
					MatchPrefixSet: config.MatchPrefixSet{
						PrefixSet: "podcidrprefixset",
					},
					MatchNeighborSet: config.MatchNeighborSet{
						NeighborSet: "externalpeerset",
					},
				},
				Actions: config.Actions{
					RouteDisposition: config.ROUTE_DISPOSITION_ACCEPT_ROUTE,
				},
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

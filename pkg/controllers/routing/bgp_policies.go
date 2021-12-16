package routing

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	v1core "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"github.com/cloudnativelabs/kube-router/pkg/utils"
)

// AddPolicies adds BGP import and export policies
func (nrc *NetworkRoutingController) AddPolicies() error {
	// we are rr server do not add export policies
	if nrc.bgpRRServer {
		return nil
	}

	err := nrc.addPodCidrDefinedSet()
	if err != nil {
		klog.Errorf("Failed to add `podcidrdefinedset` defined set: %s", err)
	}

	err = nrc.addServiceVIPsDefinedSet()
	if err != nil {
		klog.Errorf("Failed to add `servicevipsdefinedset` defined set: %s", err)
	}

	err = nrc.addDefaultRouteDefinedSet()
	if err != nil {
		klog.Errorf("Failed to add `defaultroutedefinedset` defined set: %s", err)
	}

	err = nrc.addCustomImportRejectDefinedSet()
	if err != nil {
		klog.Errorf("Failed to add `customimportrejectdefinedset` defined set: %s", err)
	}

	iBGPPeerCIDRs, err := nrc.addiBGPPeersDefinedSet()
	if err != nil {
		klog.Errorf("Failed to add `iBGPpeerset` defined set: %s", err)
	}

	externalBGPPeerCIDRs, err := nrc.addExternalBGPPeersDefinedSet()
	if err != nil {
		klog.Errorf("Failed to add `externalpeerset` defined set: %s", err)
	}

	err = nrc.addAllBGPPeersDefinedSet(iBGPPeerCIDRs, externalBGPPeerCIDRs)
	if err != nil {
		klog.Errorf("Failed to add `allpeerset` defined set: %s", err)
	}

	err = nrc.addExportPolicies()
	if err != nil {
		return err
	}

	err = nrc.addImportPolicies()
	if err != nil {
		return err
	}

	return nil
}

// create a defined set to represent just the pod CIDR associated with the node
func (nrc *NetworkRoutingController) addPodCidrDefinedSet() error {
	var currentDefinedSet *gobgpapi.DefinedSet
	err := nrc.bgpServer.ListDefinedSet(context.Background(),
		&gobgpapi.ListDefinedSetRequest{DefinedType: gobgpapi.DefinedType_PREFIX, Name: "podcidrdefinedset"},
		func(ds *gobgpapi.DefinedSet) {
			currentDefinedSet = ds
		})
	if err != nil {
		return err
	}
	if currentDefinedSet == nil {
		cidrLen, err := strconv.Atoi(strings.Split(nrc.podCidr, "/")[1])
		if err != nil || cidrLen < 0 || cidrLen > 32 {
			return fmt.Errorf("the pod CIDR IP given is not a proper mask: %d", cidrLen)
		}
		podCidrDefinedSet := &gobgpapi.DefinedSet{
			DefinedType: gobgpapi.DefinedType_PREFIX,
			Name:        "podcidrdefinedset",
			Prefixes: []*gobgpapi.Prefix{
				{
					IpPrefix:      nrc.podCidr,
					MaskLengthMin: uint32(cidrLen),
					MaskLengthMax: uint32(cidrLen),
				},
			},
		}
		return nrc.bgpServer.AddDefinedSet(context.Background(),
			&gobgpapi.AddDefinedSetRequest{DefinedSet: podCidrDefinedSet})
	}
	return nil
}

// create a defined set to represent all the advertisable IP associated with the services
func (nrc *NetworkRoutingController) addServiceVIPsDefinedSet() error {
	var currentDefinedSet *gobgpapi.DefinedSet
	err := nrc.bgpServer.ListDefinedSet(context.Background(),
		&gobgpapi.ListDefinedSetRequest{DefinedType: gobgpapi.DefinedType_PREFIX, Name: "servicevipsdefinedset"},
		func(ds *gobgpapi.DefinedSet) {
			currentDefinedSet = ds
		})
	if err != nil {
		return err
	}
	advIPPrefixList := make([]*gobgpapi.Prefix, 0)
	advIps, _, _ := nrc.getAllVIPs()
	for _, ip := range advIps {
		advIPPrefixList = append(advIPPrefixList,
			&gobgpapi.Prefix{IpPrefix: ip + "/32", MaskLengthMin: 32, MaskLengthMax: 32})
	}
	if currentDefinedSet == nil {
		clusterIPPrefixSet := &gobgpapi.DefinedSet{
			DefinedType: gobgpapi.DefinedType_PREFIX,
			Name:        "servicevipsdefinedset",
			Prefixes:    advIPPrefixList,
		}
		return nrc.bgpServer.AddDefinedSet(context.Background(),
			&gobgpapi.AddDefinedSetRequest{DefinedSet: clusterIPPrefixSet})
	}

	currentPrefixes := currentDefinedSet.Prefixes
	sort.SliceStable(advIPPrefixList, func(i, j int) bool {
		return advIPPrefixList[i].IpPrefix < advIPPrefixList[j].IpPrefix
	})
	sort.SliceStable(currentPrefixes, func(i, j int) bool {
		return currentPrefixes[i].IpPrefix < currentPrefixes[j].IpPrefix
	})
	if reflect.DeepEqual(advIPPrefixList, currentPrefixes) {
		return nil
	}
	toAdd := make([]*gobgpapi.Prefix, 0)
	toDelete := make([]*gobgpapi.Prefix, 0)
	for _, prefix := range advIPPrefixList {
		add := true
		for _, currentPrefix := range currentDefinedSet.Prefixes {
			if currentPrefix.IpPrefix == prefix.IpPrefix {
				add = false
			}
		}
		if add {
			toAdd = append(toAdd, prefix)
		}
	}
	for _, currentPrefix := range currentDefinedSet.Prefixes {
		shouldDelete := true
		for _, prefix := range advIPPrefixList {
			if currentPrefix.IpPrefix == prefix.IpPrefix {
				shouldDelete = false
			}
		}
		if shouldDelete {
			toDelete = append(toDelete, currentPrefix)
		}
	}
	clusterIPPrefixSet := &gobgpapi.DefinedSet{
		DefinedType: gobgpapi.DefinedType_PREFIX,
		Name:        "servicevipsdefinedset",
		Prefixes:    toAdd,
	}
	err = nrc.bgpServer.AddDefinedSet(context.Background(),
		&gobgpapi.AddDefinedSetRequest{DefinedSet: clusterIPPrefixSet})
	if err != nil {
		return err
	}
	clusterIPPrefixSet = &gobgpapi.DefinedSet{
		DefinedType: gobgpapi.DefinedType_PREFIX,
		Name:        "servicevipsdefinedset",
		Prefixes:    toDelete,
	}
	err = nrc.bgpServer.DeleteDefinedSet(context.Background(),
		&gobgpapi.DeleteDefinedSetRequest{DefinedSet: clusterIPPrefixSet, All: false})
	if err != nil {
		return err
	}

	return nil
}

// create a defined set to represent just the host default route
func (nrc *NetworkRoutingController) addDefaultRouteDefinedSet() error {
	var currentDefinedSet *gobgpapi.DefinedSet
	err := nrc.bgpServer.ListDefinedSet(context.Background(),
		&gobgpapi.ListDefinedSetRequest{DefinedType: gobgpapi.DefinedType_PREFIX, Name: "defaultroutedefinedset"},
		func(ds *gobgpapi.DefinedSet) {
			currentDefinedSet = ds
		})
	if err != nil {
		return err
	}
	if currentDefinedSet == nil {
		cidrLen := 0
		defaultRouteDefinedSet := &gobgpapi.DefinedSet{
			DefinedType: gobgpapi.DefinedType_PREFIX,
			Name:        "defaultroutedefinedset",
			Prefixes: []*gobgpapi.Prefix{
				{
					IpPrefix:      "0.0.0.0/0",
					MaskLengthMin: uint32(cidrLen),
					MaskLengthMax: uint32(cidrLen),
				},
			},
		}
		return nrc.bgpServer.AddDefinedSet(context.Background(),
			&gobgpapi.AddDefinedSetRequest{DefinedSet: defaultRouteDefinedSet})
	}
	return nil
}

// create a defined set to represent custom annotated routes to be rejected on import
func (nrc *NetworkRoutingController) addCustomImportRejectDefinedSet() error {
	var currentDefinedSet *gobgpapi.DefinedSet
	err := nrc.bgpServer.ListDefinedSet(context.Background(),
		&gobgpapi.ListDefinedSetRequest{DefinedType: gobgpapi.DefinedType_PREFIX, Name: "customimportrejectdefinedset"},
		func(ds *gobgpapi.DefinedSet) {
			currentDefinedSet = ds
		})
	if err != nil {
		return err
	}
	if currentDefinedSet == nil {
		prefixes := make([]*gobgpapi.Prefix, 0)
		for _, ipNet := range nrc.nodeCustomImportRejectIPNets {
			prefix := new(gobgpapi.Prefix)
			prefix.IpPrefix = ipNet.String()
			mask, _ := ipNet.Mask.Size()
			prefix.MaskLengthMin = uint32(mask)
			prefix.MaskLengthMax = uint32(ipv4MaskMinBits)
			prefixes = append(prefixes, prefix)
		}
		customImportRejectDefinedSet := &gobgpapi.DefinedSet{
			DefinedType: gobgpapi.DefinedType_PREFIX,
			Name:        "customimportrejectdefinedset",
			Prefixes:    prefixes,
		}
		return nrc.bgpServer.AddDefinedSet(context.Background(),
			&gobgpapi.AddDefinedSetRequest{DefinedSet: customImportRejectDefinedSet})
	}
	return nil
}

func (nrc *NetworkRoutingController) addiBGPPeersDefinedSet() ([]string, error) {
	iBGPPeerCIDRs := make([]string, 0)
	if !nrc.bgpEnableInternal {
		return iBGPPeerCIDRs, nil
	}

	// Get the current list of the nodes from the local cache
	nodes := nrc.nodeLister.List()
	for _, node := range nodes {
		nodeObj := node.(*v1core.Node)
		nodeIP, err := utils.GetNodeIP(nodeObj)
		if err != nil {
			klog.Errorf("Failed to find a node IP and therefore cannot add internal BGP Peer: %v", err)
			continue
		}
		iBGPPeerCIDRs = append(iBGPPeerCIDRs, nodeIP.String()+"/32")
	}

	var currentDefinedSet *gobgpapi.DefinedSet
	err := nrc.bgpServer.ListDefinedSet(context.Background(),
		&gobgpapi.ListDefinedSetRequest{DefinedType: gobgpapi.DefinedType_NEIGHBOR, Name: "iBGPpeerset"},
		func(ds *gobgpapi.DefinedSet) {
			currentDefinedSet = ds
		})
	if err != nil {
		return iBGPPeerCIDRs, err
	}
	if currentDefinedSet == nil {
		iBGPPeerNS := &gobgpapi.DefinedSet{
			DefinedType: gobgpapi.DefinedType_NEIGHBOR,
			Name:        "iBGPpeerset",
			List:        iBGPPeerCIDRs,
		}
		err = nrc.bgpServer.AddDefinedSet(context.Background(), &gobgpapi.AddDefinedSetRequest{DefinedSet: iBGPPeerNS})
		return iBGPPeerCIDRs, err
	}

	currentCIDRs := currentDefinedSet.List
	sort.Strings(iBGPPeerCIDRs)
	sort.Strings(currentCIDRs)
	if reflect.DeepEqual(iBGPPeerCIDRs, currentCIDRs) {
		return iBGPPeerCIDRs, nil
	}
	toAdd := make([]string, 0)
	toDelete := make([]string, 0)
	for _, prefix := range iBGPPeerCIDRs {
		add := true
		for _, currentPrefix := range currentDefinedSet.List {
			if prefix == currentPrefix {
				add = false
			}
		}
		if add {
			toAdd = append(toAdd, prefix)
		}
	}
	for _, currentPrefix := range currentDefinedSet.List {
		shouldDelete := true
		for _, prefix := range iBGPPeerCIDRs {
			if currentPrefix == prefix {
				shouldDelete = false
			}
		}
		if shouldDelete {
			toDelete = append(toDelete, currentPrefix)
		}
	}
	iBGPPeerNS := &gobgpapi.DefinedSet{
		DefinedType: gobgpapi.DefinedType_NEIGHBOR,
		Name:        "iBGPpeerset",
		List:        toAdd,
	}
	err = nrc.bgpServer.AddDefinedSet(context.Background(), &gobgpapi.AddDefinedSetRequest{DefinedSet: iBGPPeerNS})
	if err != nil {
		return iBGPPeerCIDRs, err
	}
	iBGPPeerNS = &gobgpapi.DefinedSet{
		DefinedType: gobgpapi.DefinedType_NEIGHBOR,
		Name:        "iBGPpeerset",
		List:        toDelete,
	}
	err = nrc.bgpServer.DeleteDefinedSet(context.Background(),
		&gobgpapi.DeleteDefinedSetRequest{DefinedSet: iBGPPeerNS, All: false})
	if err != nil {
		return iBGPPeerCIDRs, err
	}
	return iBGPPeerCIDRs, nil
}

func (nrc *NetworkRoutingController) addExternalBGPPeersDefinedSet() ([]string, error) {

	var currentDefinedSet *gobgpapi.DefinedSet
	externalBgpPeers := make([]string, 0)
	externalBGPPeerCIDRs := make([]string, 0)
	err := nrc.bgpServer.ListDefinedSet(context.Background(),
		&gobgpapi.ListDefinedSetRequest{DefinedType: gobgpapi.DefinedType_NEIGHBOR, Name: "externalpeerset"},
		func(ds *gobgpapi.DefinedSet) {
			currentDefinedSet = ds
		})
	if err != nil {
		return externalBGPPeerCIDRs, err
	}
	if len(nrc.globalPeerRouters) > 0 {
		for _, peer := range nrc.globalPeerRouters {
			externalBgpPeers = append(externalBgpPeers, peer.Conf.NeighborAddress)
		}
	}
	if len(nrc.nodePeerRouters) > 0 {
		externalBgpPeers = append(externalBgpPeers, nrc.nodePeerRouters...)
	}
	if len(externalBgpPeers) == 0 {
		return externalBGPPeerCIDRs, nil
	}
	for _, peer := range externalBgpPeers {
		externalBGPPeerCIDRs = append(externalBGPPeerCIDRs, peer+"/32")
	}
	if currentDefinedSet == nil {
		eBGPPeerNS := &gobgpapi.DefinedSet{
			DefinedType: gobgpapi.DefinedType_NEIGHBOR,
			Name:        "externalpeerset",
			List:        externalBGPPeerCIDRs,
		}
		err = nrc.bgpServer.AddDefinedSet(context.Background(), &gobgpapi.AddDefinedSetRequest{DefinedSet: eBGPPeerNS})
		return externalBGPPeerCIDRs, err
	}

	return externalBGPPeerCIDRs, nil
}

// a slice of all peers is used as a match condition for reject statement of servicevipsdefinedset import policy
func (nrc *NetworkRoutingController) addAllBGPPeersDefinedSet(iBGPPeerCIDRs, externalBGPPeerCIDRs []string) error {
	var currentDefinedSet *gobgpapi.DefinedSet
	err := nrc.bgpServer.ListDefinedSet(context.Background(),
		&gobgpapi.ListDefinedSetRequest{DefinedType: gobgpapi.DefinedType_NEIGHBOR, Name: "allpeerset"},
		func(ds *gobgpapi.DefinedSet) {
			currentDefinedSet = ds
		})
	if err != nil {
		return err
	}
	// nolint:gocritic // We intentionally append to a different array here so as to not change the passed
	// in externalBGPPeerCIDRs
	allBgpPeers := append(externalBGPPeerCIDRs, iBGPPeerCIDRs...)
	if currentDefinedSet == nil {
		allPeerNS := &gobgpapi.DefinedSet{
			DefinedType: gobgpapi.DefinedType_NEIGHBOR,
			Name:        "allpeerset",
			List:        allBgpPeers,
		}
		return nrc.bgpServer.AddDefinedSet(context.Background(), &gobgpapi.AddDefinedSetRequest{DefinedSet: allPeerNS})
	}

	toAdd := make([]string, 0)
	toDelete := make([]string, 0)
	for _, peer := range allBgpPeers {
		add := true
		for _, currentPeer := range currentDefinedSet.List {
			if peer == currentPeer {
				add = false
			}
		}
		if add {
			toAdd = append(toAdd, peer)
		}
	}
	for _, currentPeer := range currentDefinedSet.List {
		shouldDelete := true
		for _, peer := range allBgpPeers {
			if peer == currentPeer {
				shouldDelete = false
			}
		}
		if shouldDelete {
			toDelete = append(toDelete, currentPeer)
		}
	}
	allPeerNS := &gobgpapi.DefinedSet{
		DefinedType: gobgpapi.DefinedType_NEIGHBOR,
		Name:        "allpeerset",
		List:        toAdd,
	}
	err = nrc.bgpServer.AddDefinedSet(context.Background(), &gobgpapi.AddDefinedSetRequest{DefinedSet: allPeerNS})
	if err != nil {
		return err
	}
	allPeerNS = &gobgpapi.DefinedSet{
		DefinedType: gobgpapi.DefinedType_NEIGHBOR,
		Name:        "allpeerset",
		List:        toDelete,
	}
	err = nrc.bgpServer.DeleteDefinedSet(context.Background(),
		&gobgpapi.DeleteDefinedSetRequest{DefinedSet: allPeerNS, All: false})
	if err != nil {
		return err
	}
	return nil
}

// BGP export policies are added so that following conditions are met:
//
// - by default export of all routes from the RIB to the neighbour's is denied, and explicitly statements are added
//   to permit the desired routes to be exported
// - each node is allowed to advertise its assigned pod CIDR's to all of its iBGP peer neighbours with same
//   ASN if --enable-ibgp=true
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
	statements := make([]*gobgpapi.Statement, 0)

	var bgpActions gobgpapi.Actions
	if nrc.pathPrepend {
		prependAsn, err := strconv.ParseUint(nrc.pathPrependAS, 10, asnMaxBitSize)
		if err != nil {
			return errors.New("Invalid value for kube-router.io/path-prepend.as: " + err.Error())
		}
		bgpActions = gobgpapi.Actions{
			AsPrepend: &gobgpapi.AsPrependAction{
				Asn:    uint32(prependAsn),
				Repeat: uint32(nrc.pathPrependCount),
			},
		}
	}

	if nrc.bgpEnableInternal {
		actions := gobgpapi.Actions{
			RouteAction: gobgpapi.RouteAction_ACCEPT,
		}
		if nrc.overrideNextHop {
			actions.Nexthop = &gobgpapi.NexthopAction{Self: true}
		}
		// statement to represent the export policy to permit advertising node's pod CIDR
		statements = append(statements,
			&gobgpapi.Statement{
				Conditions: &gobgpapi.Conditions{
					PrefixSet: &gobgpapi.MatchSet{
						Type: gobgpapi.MatchSet_ANY,
						Name: "podcidrdefinedset",
					},
					NeighborSet: &gobgpapi.MatchSet{
						Type: gobgpapi.MatchSet_ANY,
						Name: "iBGPpeerset",
					},
				},
				Actions: &actions,
			})
	}

	if len(nrc.globalPeerRouters) > 0 || len(nrc.nodePeerRouters) > 0 {

		bgpActions.RouteAction = gobgpapi.RouteAction_ACCEPT
		if nrc.overrideNextHop {
			bgpActions.Nexthop = &gobgpapi.NexthopAction{Self: true}
		}

		// set BGP communities for the routes advertised to peers for VIPs
		if len(nrc.nodeCommunities) > 0 {
			bgpActions.Community = &gobgpapi.CommunityAction{
				Type:        gobgpapi.CommunityAction_ADD,
				Communities: nrc.nodeCommunities,
			}
		}

		// statement to represent the export policy to permit advertising cluster IP's
		// only to the global BGP peer or node specific BGP peer
		statements = append(statements, &gobgpapi.Statement{
			Conditions: &gobgpapi.Conditions{
				PrefixSet: &gobgpapi.MatchSet{
					Type: gobgpapi.MatchSet_ANY,
					Name: "servicevipsdefinedset",
				},
				NeighborSet: &gobgpapi.MatchSet{
					Type: gobgpapi.MatchSet_ANY,
					Name: "externalpeerset",
				},
			},
			Actions: &bgpActions,
		})

		if nrc.advertisePodCidr {
			actions := gobgpapi.Actions{
				RouteAction: gobgpapi.RouteAction_ACCEPT,
			}
			// set BGP communities for the routes advertised to peers for the pod network
			if len(nrc.nodeCommunities) > 0 {
				actions.Community = &gobgpapi.CommunityAction{
					Type:        gobgpapi.CommunityAction_ADD,
					Communities: nrc.nodeCommunities,
				}
			}
			if nrc.overrideNextHop {
				actions.Nexthop = &gobgpapi.NexthopAction{Self: true}
			}
			statements = append(statements, &gobgpapi.Statement{
				Conditions: &gobgpapi.Conditions{
					PrefixSet: &gobgpapi.MatchSet{
						Type: gobgpapi.MatchSet_ANY,
						Name: "podcidrdefinedset",
					},
					NeighborSet: &gobgpapi.MatchSet{
						Type: gobgpapi.MatchSet_ANY,
						Name: "externalpeerset",
					},
				},
				Actions: &actions,
			})
		}
	}

	definition := gobgpapi.Policy{
		Name:       "kube_router_export",
		Statements: statements,
	}

	policyAlreadyExists := false
	checkExistingPolicy := func(existingPolicy *gobgpapi.Policy) {
		if existingPolicy.Name == "kube_router_export" {
			policyAlreadyExists = true
		}
	}
	err := nrc.bgpServer.ListPolicy(context.Background(), &gobgpapi.ListPolicyRequest{}, checkExistingPolicy)
	if err != nil {
		return errors.New("Failed to verify if kube-router BGP export policy exists: " + err.Error())
	}

	if !policyAlreadyExists {
		err = nrc.bgpServer.AddPolicy(context.Background(), &gobgpapi.AddPolicyRequest{Policy: &definition})
		if err != nil {
			return errors.New("Failed to add policy: " + err.Error())
		}
	}

	policyAssignmentExists := false
	checkExistingPolicyAssignment := func(existingPolicyAssignment *gobgpapi.PolicyAssignment) {
		for _, policy := range existingPolicyAssignment.Policies {
			if policy.Name == "kube_router_export" {
				policyAssignmentExists = true
			}
		}
	}
	err = nrc.bgpServer.ListPolicyAssignment(context.Background(),
		&gobgpapi.ListPolicyAssignmentRequest{Name: "global", Direction: gobgpapi.PolicyDirection_EXPORT},
		checkExistingPolicyAssignment)
	if err != nil {
		return errors.New("Failed to verify if kube-router BGP export policy assignment exists: " + err.Error())
	}

	policyAssignment := gobgpapi.PolicyAssignment{
		Name:          "global",
		Direction:     gobgpapi.PolicyDirection_EXPORT,
		Policies:      []*gobgpapi.Policy{&definition},
		DefaultAction: gobgpapi.RouteAction_REJECT,
	}
	if !policyAssignmentExists {
		err = nrc.bgpServer.AddPolicyAssignment(context.Background(),
			&gobgpapi.AddPolicyAssignmentRequest{Assignment: &policyAssignment})
		if err != nil {
			return errors.New("Failed to add policy assignment: " + err.Error())
		}
	}

	return nil
}

// BGP import policies are added so that the following conditions are met:
// - do not import Service VIPs advertised from any peers, instead each kube-router originates and injects
//   Service VIPs into local rib.
func (nrc *NetworkRoutingController) addImportPolicies() error {
	statements := make([]*gobgpapi.Statement, 0)

	actions := gobgpapi.Actions{
		RouteAction: gobgpapi.RouteAction_REJECT,
	}
	statements = append(statements, &gobgpapi.Statement{
		Conditions: &gobgpapi.Conditions{
			PrefixSet: &gobgpapi.MatchSet{
				Type: gobgpapi.MatchSet_ANY,
				Name: "servicevipsdefinedset",
			},
			NeighborSet: &gobgpapi.MatchSet{
				Type: gobgpapi.MatchSet_ANY,
				Name: "allpeerset",
			},
		},
		Actions: &actions,
	})

	statements = append(statements, &gobgpapi.Statement{
		Conditions: &gobgpapi.Conditions{
			PrefixSet: &gobgpapi.MatchSet{
				Type: gobgpapi.MatchSet_ANY,
				Name: "defaultroutedefinedset",
			},
			NeighborSet: &gobgpapi.MatchSet{
				Type: gobgpapi.MatchSet_ANY,
				Name: "allpeerset",
			},
		},
		Actions: &actions,
	})

	if len(nrc.nodeCustomImportRejectIPNets) > 0 {
		statements = append(statements, &gobgpapi.Statement{
			Conditions: &gobgpapi.Conditions{
				PrefixSet: &gobgpapi.MatchSet{
					Name: "customimportrejectdefinedset",
					Type: gobgpapi.MatchSet_ANY,
				},
				NeighborSet: &gobgpapi.MatchSet{
					Type: gobgpapi.MatchSet_ANY,
					Name: "allpeerset",
				},
			},
			Actions: &actions,
		})
	}

	definition := gobgpapi.Policy{
		Name:       "kube_router_import",
		Statements: statements,
	}

	policyAlreadyExists := false
	checkExistingPolicy := func(existingPolicy *gobgpapi.Policy) {
		if existingPolicy.Name == "kube_router_import" {
			policyAlreadyExists = true
		}
	}
	err := nrc.bgpServer.ListPolicy(context.Background(), &gobgpapi.ListPolicyRequest{}, checkExistingPolicy)
	if err != nil {
		return errors.New("Failed to verify if kube-router BGP import policy exists: " + err.Error())
	}

	if !policyAlreadyExists {
		err = nrc.bgpServer.AddPolicy(context.Background(), &gobgpapi.AddPolicyRequest{Policy: &definition})
		if err != nil {
			return errors.New("Failed to add policy: " + err.Error())
		}
	}

	policyAssignmentExists := false
	checkExistingPolicyAssignment := func(existingPolicyAssignment *gobgpapi.PolicyAssignment) {
		for _, policy := range existingPolicyAssignment.Policies {
			if policy.Name == "kube_router_import" {
				policyAssignmentExists = true
			}
		}
	}
	err = nrc.bgpServer.ListPolicyAssignment(context.Background(),
		&gobgpapi.ListPolicyAssignmentRequest{Name: "global", Direction: gobgpapi.PolicyDirection_IMPORT},
		checkExistingPolicyAssignment)
	if err != nil {
		return errors.New("Failed to verify if kube-router BGP import policy assignment exists: " + err.Error())
	}

	policyAssignment := gobgpapi.PolicyAssignment{
		Name:          "global",
		Direction:     gobgpapi.PolicyDirection_IMPORT,
		Policies:      []*gobgpapi.Policy{&definition},
		DefaultAction: gobgpapi.RouteAction_ACCEPT,
	}
	if !policyAssignmentExists {
		err = nrc.bgpServer.AddPolicyAssignment(context.Background(),
			&gobgpapi.AddPolicyAssignmentRequest{Assignment: &policyAssignment})
		if err != nil {
			return errors.New("Failed to add policy assignment: " + err.Error())
		}
	}

	return nil
}

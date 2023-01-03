package routing

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strconv"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	v1core "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"github.com/cloudnativelabs/kube-router/pkg/utils"
)

const (
	podCIDRSet   = "podcidrdefinedset"
	podCIDRSetV6 = "podcidrdefinedsetv6"

	serviceVIPsSet   = "servicevipsdefinedset"
	serviceVIPsSetV6 = "servicevipsdefinedsetv6"

	allPeerSet        = "allpeerset"
	allPeerSetV6      = "allpeersetv6"
	externalPeerSet   = "externalpeerset"
	externalPeerSetV6 = "externalpeersetv6"
	iBGPPeerSet       = "iBGPpeerset"
	iBGPPeerSetV6     = "iBGPpeersetv6"

	customImportRejectSet = "customimportrejectdefinedset"
	defaultRouteSet       = "defaultroutedefinedset"
	defaultRouteSetV6     = "defaultroutedefinedsetv6"

	kubeRouterExportPolicy = "kube_router_export"
	kubeRouterImportPolicy = "kube_router_import"

	maxIPv4MaskSize = uint32(32)
	maxIPv6MaskSize = uint32(128)
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

	for setName, cidrs := range map[string][]string{
		podCIDRSet:   nrc.podIPv4CIDRs,
		podCIDRSetV6: nrc.podIPv6CIDRs,
	} {
		err := nrc.bgpServer.ListDefinedSet(context.Background(),
			&gobgpapi.ListDefinedSetRequest{DefinedType: gobgpapi.DefinedType_PREFIX, Name: setName},
			func(ds *gobgpapi.DefinedSet) {
				currentDefinedSet = ds
			})
		if err != nil {
			return err
		}
		if currentDefinedSet == nil {
			var prefixes []*gobgpapi.Prefix
			for _, cidr := range cidrs {
				_, ipNet, err := net.ParseCIDR(cidr)
				if err != nil {
					return fmt.Errorf("couldn't parse CIDR: %s - %v", cidr, err)
				}
				cidrLen, _ := ipNet.Mask.Size()
				var cidrMax int
				if setName == podCIDRSet {
					cidrMax = 32
				} else {
					cidrMax = 128
				}
				if cidrLen < 0 || cidrLen > cidrMax {
					return fmt.Errorf("the pod CIDR IP given is not a proper mask: %d", cidrLen)
				}
				prefixes = append(prefixes, &gobgpapi.Prefix{
					IpPrefix:      cidr,
					MaskLengthMin: uint32(cidrLen),
					MaskLengthMax: uint32(cidrLen),
				})
			}
			podCidrDefinedSet := &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_PREFIX,
				Name:        setName,
				Prefixes:    prefixes,
			}
			err = nrc.bgpServer.AddDefinedSet(context.Background(),
				&gobgpapi.AddDefinedSetRequest{DefinedSet: podCidrDefinedSet})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// create a defined set to represent all the advertisable IP associated with the services
func (nrc *NetworkRoutingController) addServiceVIPsDefinedSet() error {
	for setName, cidrMask := range map[string]uint32{
		serviceVIPsSet:   maxIPv4MaskSize,
		serviceVIPsSetV6: maxIPv6MaskSize,
	} {
		currentDefinedSet, err := nrc.getDefinedSetFromGoBGP(setName, gobgpapi.DefinedType_PREFIX)
		if err != nil {
			return err
		}

		advIPPrefixList := make([]*gobgpapi.Prefix, 0)
		advIps, _, _ := nrc.getAllVIPs()
		for _, ipStr := range advIps {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				// nothing to do for invalid IPs
				klog.Warningf("found an invalid IP address in list of service VIPs returned from k8s: %s skipping",
					ipStr)
				continue
			}
			switch {
			// Only add IPv4 VIPs when we are populating the serviceVIPsSet set
			case ip.To4() != nil && setName == serviceVIPsSet:
				advIPPrefixList = append(advIPPrefixList,
					&gobgpapi.Prefix{
						IpPrefix:      fmt.Sprintf("%s/%d", ip, cidrMask),
						MaskLengthMin: cidrMask,
						MaskLengthMax: cidrMask,
					})
			// Only add IPv6 VIPs when we are populating the serviceVIPsSetV6 set
			case ip.To4() == nil && ip.To16() != nil && setName == serviceVIPsSetV6:
				advIPPrefixList = append(advIPPrefixList,
					&gobgpapi.Prefix{
						IpPrefix:      fmt.Sprintf("%s/%d", ip, cidrMask),
						MaskLengthMin: cidrMask,
						MaskLengthMax: cidrMask,
					})
			}
		}
		if currentDefinedSet == nil {
			clusterIPPrefixSet := &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_PREFIX,
				Name:        setName,
				Prefixes:    advIPPrefixList,
			}
			err = nrc.bgpServer.AddDefinedSet(context.Background(),
				&gobgpapi.AddDefinedSetRequest{DefinedSet: clusterIPPrefixSet})
			if err != nil {
				return err
			}
			continue
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
			Name:        setName,
			Prefixes:    toAdd,
		}
		err = nrc.bgpServer.AddDefinedSet(context.Background(),
			&gobgpapi.AddDefinedSetRequest{DefinedSet: clusterIPPrefixSet})
		if err != nil {
			return err
		}
		clusterIPPrefixSet = &gobgpapi.DefinedSet{
			DefinedType: gobgpapi.DefinedType_PREFIX,
			Name:        setName,
			Prefixes:    toDelete,
		}
		err = nrc.bgpServer.DeleteDefinedSet(context.Background(),
			&gobgpapi.DeleteDefinedSetRequest{DefinedSet: clusterIPPrefixSet, All: false})
		if err != nil {
			return err
		}
	}

	return nil
}

// create a defined set to represent just the host default route
func (nrc *NetworkRoutingController) addDefaultRouteDefinedSet() error {
	for setName, defaultRoute := range map[string]string{
		defaultRouteSet:   "0.0.0.0/0",
		defaultRouteSetV6: "::/0",
	} {
		currentDefinedSet, err := nrc.getDefinedSetFromGoBGP(setName, gobgpapi.DefinedType_PREFIX)
		if err != nil {
			return err
		}

		if currentDefinedSet == nil {
			cidrLen := 0
			defaultRouteDefinedSet := &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_PREFIX,
				Name:        setName,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      defaultRoute,
						MaskLengthMin: uint32(cidrLen),
						MaskLengthMax: uint32(cidrLen),
					},
				},
			}
			err = nrc.bgpServer.AddDefinedSet(context.Background(),
				&gobgpapi.AddDefinedSetRequest{DefinedSet: defaultRouteDefinedSet})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// create a defined set to represent custom annotated routes to be rejected on import
func (nrc *NetworkRoutingController) addCustomImportRejectDefinedSet() error {
	var currentDefinedSet *gobgpapi.DefinedSet
	currentDefinedSet, err := nrc.getDefinedSetFromGoBGP(customImportRejectSet, gobgpapi.DefinedType_PREFIX)
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
			Name:        customImportRejectSet,
			Prefixes:    prefixes,
		}
		return nrc.bgpServer.AddDefinedSet(context.Background(),
			&gobgpapi.AddDefinedSetRequest{DefinedSet: customImportRejectDefinedSet})
	}
	return nil
}

func (nrc *NetworkRoutingController) addiBGPPeersDefinedSet() (map[v1core.IPFamily][]string, error) {
	iBGPPeerCIDRs := make(map[v1core.IPFamily][]string)
	if !nrc.bgpEnableInternal {
		return iBGPPeerCIDRs, nil
	}

	// Get the current list of the nodes from the local cache
	nodes := nrc.nodeLister.List()
	for _, node := range nodes {
		nodeObj := node.(*v1core.Node)
		nodeIP, err := utils.GetPrimaryNodeIP(nodeObj)
		if err != nil {
			klog.Errorf("Failed to find a node IP and therefore cannot add internal BGP Peer: %v", err)
			continue
		}
		if nodeIP.To4() != nil {
			iBGPPeerCIDRs[v1core.IPv4Protocol] = append(iBGPPeerCIDRs[v1core.IPv4Protocol], nodeIP.String()+"/32")
		} else {
			iBGPPeerCIDRs[v1core.IPv6Protocol] = append(iBGPPeerCIDRs[v1core.IPv6Protocol], nodeIP.String()+"/128")
		}
	}

	for family, setName := range map[v1core.IPFamily]string{
		v1core.IPv4Protocol: iBGPPeerSet,
		v1core.IPv6Protocol: iBGPPeerSetV6,
	} {
		currentDefinedSet, err := nrc.getDefinedSetFromGoBGP(setName, gobgpapi.DefinedType_NEIGHBOR)
		if err != nil {
			return iBGPPeerCIDRs, err
		}

		if currentDefinedSet == nil {
			iBGPPeerNS := &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_NEIGHBOR,
				Name:        setName,
				List:        iBGPPeerCIDRs[family],
			}
			err = nrc.bgpServer.AddDefinedSet(context.Background(),
				&gobgpapi.AddDefinedSetRequest{DefinedSet: iBGPPeerNS})
			if err != nil {
				return iBGPPeerCIDRs, err
			}
			continue
		}

		currentCIDRs := currentDefinedSet.List
		sort.Strings(iBGPPeerCIDRs[family])
		sort.Strings(currentCIDRs)
		if reflect.DeepEqual(iBGPPeerCIDRs, currentCIDRs) {
			return iBGPPeerCIDRs, nil
		}
		toAdd := make([]string, 0)
		toDelete := make([]string, 0)
		for _, prefix := range iBGPPeerCIDRs[family] {
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
			for _, prefix := range iBGPPeerCIDRs[family] {
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
			Name:        setName,
			List:        toAdd,
		}
		err = nrc.bgpServer.AddDefinedSet(context.Background(), &gobgpapi.AddDefinedSetRequest{DefinedSet: iBGPPeerNS})
		if err != nil {
			return iBGPPeerCIDRs, err
		}
		iBGPPeerNS = &gobgpapi.DefinedSet{
			DefinedType: gobgpapi.DefinedType_NEIGHBOR,
			Name:        setName,
			List:        toDelete,
		}
		err = nrc.bgpServer.DeleteDefinedSet(context.Background(),
			&gobgpapi.DeleteDefinedSetRequest{DefinedSet: iBGPPeerNS, All: false})
		if err != nil {
			return iBGPPeerCIDRs, err
		}
	}
	return iBGPPeerCIDRs, nil
}

func (nrc *NetworkRoutingController) addExternalBGPPeersDefinedSet() (map[v1core.IPFamily][]string, error) {

	externalBgpPeers := make([]string, 0)
	externalBGPPeerCIDRs := make(map[v1core.IPFamily][]string)

	for family, extPeerSetName := range map[v1core.IPFamily]string{
		v1core.IPv4Protocol: externalPeerSet,
		v1core.IPv6Protocol: externalPeerSetV6} {
		currentDefinedSet, err := nrc.getDefinedSetFromGoBGP(extPeerSetName, gobgpapi.DefinedType_NEIGHBOR)
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
			ip := net.ParseIP(peer)
			if ip == nil {
				klog.Warningf("wasn't able to parse the IP of peer: %s - skipping!", peer)
				continue
			}
			if ip.To4() != nil {
				// if we're not currently loading the IPv4 family, move on
				if family != v1core.IPv4Protocol {
					continue
				}
				externalBGPPeerCIDRs[family] = append(externalBGPPeerCIDRs[family], peer+"/32")
			} else if ip.To16() != nil {
				// if we're not currently loading the IPv6 family, move on
				if family != v1core.IPv6Protocol {
					continue
				}
				externalBGPPeerCIDRs[family] = append(externalBGPPeerCIDRs[family], peer+"/128")
			}
		}
		if currentDefinedSet == nil {
			eBGPPeerNS := &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_NEIGHBOR,
				Name:        extPeerSetName,
				List:        externalBGPPeerCIDRs[family],
			}
			err = nrc.bgpServer.AddDefinedSet(context.Background(),
				&gobgpapi.AddDefinedSetRequest{DefinedSet: eBGPPeerNS})
			if err != nil {
				return externalBGPPeerCIDRs, err
			}
		}
	}

	return externalBGPPeerCIDRs, nil
}

// a slice of all peers is used as a match condition for reject statement of servicevipsdefinedset import policy
func (nrc *NetworkRoutingController) addAllBGPPeersDefinedSet(
	iBGPPeerCIDRs, externalBGPPeerCIDRs map[v1core.IPFamily][]string) error {

	for family, allPeerSetName := range map[v1core.IPFamily]string{
		v1core.IPv4Protocol: allPeerSet,
		v1core.IPv6Protocol: allPeerSetV6} {
		var currentDefinedSet *gobgpapi.DefinedSet
		currentDefinedSet, err := nrc.getDefinedSetFromGoBGP(allPeerSetName, gobgpapi.DefinedType_NEIGHBOR)
		if err != nil {
			return err
		}
		//nolint:gocritic // We intentionally append to a different array here to not change the passed
		// in externalBGPPeerCIDRs
		allBgpPeers := append(externalBGPPeerCIDRs[family], iBGPPeerCIDRs[family]...)
		if currentDefinedSet == nil {
			allPeerNS := &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_NEIGHBOR,
				Name:        allPeerSetName,
				List:        allBgpPeers,
			}
			err = nrc.bgpServer.AddDefinedSet(context.Background(),
				&gobgpapi.AddDefinedSetRequest{DefinedSet: allPeerNS})
			if err != nil {
				return err
			}
			continue
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
			Name:        allPeerSetName,
			List:        toAdd,
		}
		err = nrc.bgpServer.AddDefinedSet(context.Background(), &gobgpapi.AddDefinedSetRequest{DefinedSet: allPeerNS})
		if err != nil {
			return err
		}
		allPeerNS = &gobgpapi.DefinedSet{
			DefinedType: gobgpapi.DefinedType_NEIGHBOR,
			Name:        allPeerSetName,
			List:        toDelete,
		}
		err = nrc.bgpServer.DeleteDefinedSet(context.Background(),
			&gobgpapi.DeleteDefinedSetRequest{DefinedSet: allPeerNS, All: false})
		if err != nil {
			return err
		}
	}
	return nil
}

// BGP export policies are added so that following conditions are met:
//
//   - by default export of all routes from the RIB to the neighbour's is denied, and explicitly statements are added
//     to permit the desired routes to be exported
//   - each node is allowed to advertise its assigned pod CIDR's to all of its iBGP peer neighbours with same
//     ASN if --enable-ibgp=true
//   - each node is allowed to advertise its assigned pod CIDR's to all of its external BGP peer neighbours
//     only if --advertise-pod-cidr flag is set to true
//   - each node is NOT allowed to advertise its assigned pod CIDR's to all of its external BGP peer neighbours
//     only if --advertise-pod-cidr flag is set to false
//   - each node is allowed to advertise service VIP's (cluster ip, load balancer ip, external IP) ONLY to external
//     BGP peers
//   - each node is NOT allowed to advertise service VIP's (cluster ip, load balancer ip, external IP) to
//     iBGP peers
//   - an option to allow overriding the next-hop-address with the outgoing ip for external bgp peers
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

		// statement to represent the export policy to permit advertising node's IPv4 & IPv6 pod CIDRs
		for _, podSet := range []string{podCIDRSet, podCIDRSetV6} {
			statements = append(statements,
				&gobgpapi.Statement{
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_ANY,
							Name: podSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_ANY,
							Name: iBGPPeerSet,
						},
					},
					Actions: &actions,
				})
		}
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

		for _, peerSet := range []string{externalPeerSet, externalPeerSetV6} {
			for _, serviceVIPSet := range []string{serviceVIPsSet, serviceVIPsSetV6} {
				// statement to represent the export policy to permit advertising Service VIP's
				// only to the global BGP peer or node specific BGP peer
				statements = append(statements, &gobgpapi.Statement{
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_ANY,
							Name: serviceVIPSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_ANY,
							Name: peerSet,
						},
					},
					Actions: &bgpActions,
				})
			}

			if nrc.advertisePodCidr {
				for _, podSet := range []string{podCIDRSet, podCIDRSetV6} {
					// if we are configured to advertise POD CIDRs then add export policies for all of our IPv4 and IPv6
					// peers for all IPv4 and IPv6 POD CIDRs
					statements = append(statements, &gobgpapi.Statement{
						Conditions: &gobgpapi.Conditions{
							PrefixSet: &gobgpapi.MatchSet{
								Type: gobgpapi.MatchSet_ANY,
								Name: podSet,
							},
							NeighborSet: &gobgpapi.MatchSet{
								Type: gobgpapi.MatchSet_ANY,
								Name: peerSet,
							},
						},
						Actions: &bgpActions,
					})
				}
			}
		}
	}

	definition := gobgpapi.Policy{
		Name:       kubeRouterExportPolicy,
		Statements: statements,
	}

	policyAlreadyExists := false
	checkExistingPolicy := func(existingPolicy *gobgpapi.Policy) {
		if existingPolicy.Name == kubeRouterExportPolicy {
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
			if policy.Name == kubeRouterExportPolicy {
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
//   - do not import Service VIPs advertised from any peers, instead each kube-router originates and injects
//     Service VIPs into local rib.
func (nrc *NetworkRoutingController) addImportPolicies() error {
	statements := make([]*gobgpapi.Statement, 0)

	actions := gobgpapi.Actions{
		RouteAction: gobgpapi.RouteAction_REJECT,
	}
	for _, peerSet := range []string{allPeerSet, allPeerSetV6} {
		for _, vipSet := range []string{serviceVIPsSet, serviceVIPsSetV6} {
			statements = append(statements, &gobgpapi.Statement{
				Conditions: &gobgpapi.Conditions{
					PrefixSet: &gobgpapi.MatchSet{
						Type: gobgpapi.MatchSet_ANY,
						Name: vipSet,
					},
					NeighborSet: &gobgpapi.MatchSet{
						Type: gobgpapi.MatchSet_ANY,
						Name: peerSet,
					},
				},
				Actions: &actions,
			})
		}

		statements = append(statements, &gobgpapi.Statement{
			Conditions: &gobgpapi.Conditions{
				PrefixSet: &gobgpapi.MatchSet{
					Type: gobgpapi.MatchSet_ANY,
					Name: defaultRouteSet,
				},
				NeighborSet: &gobgpapi.MatchSet{
					Type: gobgpapi.MatchSet_ANY,
					Name: peerSet,
				},
			},
			Actions: &actions,
		})

		if len(nrc.nodeCustomImportRejectIPNets) > 0 {
			statements = append(statements, &gobgpapi.Statement{
				Conditions: &gobgpapi.Conditions{
					PrefixSet: &gobgpapi.MatchSet{
						Name: customImportRejectSet,
						Type: gobgpapi.MatchSet_ANY,
					},
					NeighborSet: &gobgpapi.MatchSet{
						Type: gobgpapi.MatchSet_ANY,
						Name: peerSet,
					},
				},
				Actions: &actions,
			})
		}
	}

	definition := gobgpapi.Policy{
		Name:       kubeRouterImportPolicy,
		Statements: statements,
	}

	policyAlreadyExists := false
	checkExistingPolicy := func(existingPolicy *gobgpapi.Policy) {
		if existingPolicy.Name == kubeRouterImportPolicy {
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
			if policy.Name == kubeRouterImportPolicy {
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

// getDefinedSetFromGoBGP abstracts the logic for getting a DefinedSet object back for a given set type and name
func (nrc *NetworkRoutingController) getDefinedSetFromGoBGP(name string,
	defType gobgpapi.DefinedType) (defSet *gobgpapi.DefinedSet, err error) {
	err = nrc.bgpServer.ListDefinedSet(context.Background(),
		&gobgpapi.ListDefinedSetRequest{
			DefinedType: defType,
			Name:        name,
		}, func(ds *gobgpapi.DefinedSet) {
			defSet = ds
		})
	return
}

package routing

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	gobgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/vishvananda/netlink/nl"
	v1core "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"github.com/vishvananda/netlink"
)

// Used for processing Annotations that may contain multiple items
// Pass this the string and the delimiter
//
//nolint:unparam // while delimiter is always "," for now it provides flexibility to leave the function this way
func stringToSlice(s, d string) []string {
	ss := make([]string, 0)
	if strings.Contains(s, d) {
		ss = strings.Split(s, d)
	} else {
		ss = append(ss, s)
	}
	return ss
}

func stringSliceToIPs(s []string) ([]net.IP, error) {
	ips := make([]net.IP, 0)
	for _, ipString := range s {
		ip := net.ParseIP(ipString)
		if ip == nil {
			return nil, fmt.Errorf("could not parse \"%s\" as an IP", ipString)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func stringSliceToIPNets(s []string) ([]net.IPNet, error) {
	ipNets := make([]net.IPNet, 0)
	for _, ipNetString := range s {
		ip, ipNet, err := net.ParseCIDR(strings.TrimSpace(ipNetString))
		if err != nil {
			return nil, fmt.Errorf("could not parse \"%s\" as an CIDR", ipNetString)
		}
		if ip == nil {
			return nil, fmt.Errorf("could not parse \"%s\" as an IP", ipNetString)
		}
		ipNets = append(ipNets, *ipNet)
	}
	return ipNets, nil
}

func stringSliceToUInt32(s []string) ([]uint32, error) {
	ints := make([]uint32, 0)
	for _, intString := range s {
		newInt, err := strconv.ParseUint(intString, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("could not parse \"%s\" as an integer", intString)
		}
		ints = append(ints, uint32(newInt))
	}
	return ints, nil
}

func stringSliceB64Decode(s []string) ([]string, error) {
	ss := make([]string, 0)
	for _, b64String := range s {
		decoded, err := base64.StdEncoding.DecodeString(b64String)
		if err != nil {
			return nil, fmt.Errorf("could not parse \"%s\" as a base64 encoded string",
				b64String)
		}
		ss = append(ss, string(decoded))
	}
	return ss, nil
}

func statementsEqualByName(a, b []*gobgpapi.Statement) bool {
	// First a is in the outer loop ensuring that all members of a are in b
	for _, st1 := range a {
		st1Found := false
		for _, st2 := range b {
			if st1.Name == st2.Name {
				st1Found = true
			}
		}
		if !st1Found {
			return false
		}
	}

	// Second b is in the outer loop ensuring that all members of b are in a
	for _, st1 := range b {
		st1Found := false
		for _, st2 := range a {
			if st1.Name == st2.Name {
				st1Found = true
			}
		}
		if !st1Found {
			return false
		}
	}

	// If we've made it through both loops then we know that the statements arrays are equal
	return true
}

func getNodeSubnet(nodeIP net.IP) (net.IPNet, string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return net.IPNet{}, "", errors.New("failed to get list of links")
	}
	for _, link := range links {
		addresses, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return net.IPNet{}, "", errors.New("failed to get list of addr")
		}
		for _, addr := range addresses {
			if addr.IPNet.IP.Equal(nodeIP) {
				return *addr.IPNet, link.Attrs().Name, nil
			}
		}
	}
	return net.IPNet{}, "", errors.New("failed to find interface with specified node ip")
}

// generateTunnelName will generate a name for a tunnel interface given a node IP
// Since linux restricts interface names to 15 characters, we take the sha-256 of the node IP after removing
// non-entropic characters like '.' and ':', and then use the first 12 bytes of it. This allows us to cater to both
// long IPv4 addresses and much longer IPv6 addresses.
func generateTunnelName(nodeIP string) string {
	// remove dots from an IPv4 address
	strippedIP := strings.ReplaceAll(nodeIP, ".", "")
	// remove colons from an IPv6 address
	strippedIP = strings.ReplaceAll(strippedIP, ":", "")

	h := sha256.New()
	h.Write([]byte(strippedIP))
	sum := h.Sum(nil)

	return "tun-" + fmt.Sprintf("%x", sum)[0:11]
}

// validateCommunity takes in a string and attempts to parse a BGP community out of it in a way that is similar to
// gobgp (internal/pkg/table/policy.go:ParseCommunity()). If it is not able to parse the community information it
// returns an error.
func validateCommunity(arg string) error {
	_, err := strconv.ParseUint(arg, 10, bgpCommunityMaxSize)
	if err == nil {
		return nil
	}

	_regexpCommunity := regexp.MustCompile(`(\d+):(\d+)`)
	elems := _regexpCommunity.FindStringSubmatch(arg)
	if len(elems) == 3 {
		if _, err := strconv.ParseUint(elems[1], 10, bgpCommunityMaxPartSize); err == nil {
			if _, err = strconv.ParseUint(elems[2], 10, bgpCommunityMaxPartSize); err == nil {
				return nil
			}
		}
	}
	for _, v := range bgp.WellKnownCommunityNameMap {
		if arg == v {
			return nil
		}
	}
	return fmt.Errorf("failed to parse %s as community", arg)
}

// parseBGPNextHop takes in a GoBGP Path and parses out the destination's next hop from its attributes. If it
// can't parse a next hop IP from the GoBGP Path, it returns an error.
func parseBGPNextHop(path *gobgpapi.Path) (net.IP, error) {
	for _, pAttr := range path.GetPattrs() {
		unmarshalNew, err := pAttr.UnmarshalNew()
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal path attribute: %s", err)
		}
		switch t := unmarshalNew.(type) {
		case *gobgpapi.NextHopAttribute:
			// This is the primary way that we receive NextHops and happens when both the client and the server exchange
			// next hops on the same IP family that they negotiated BGP on
			nextHopIP := net.ParseIP(t.NextHop)
			if nextHopIP != nil && (nextHopIP.To4() != nil || nextHopIP.To16() != nil) {
				return nextHopIP, nil
			}
			return nil, fmt.Errorf("invalid nextHop address: %s", t.NextHop)
		case *gobgpapi.MpReachNLRIAttribute:
			// in the case where the server and the client are exchanging next-hops that don't relate to their primary
			// IP family, we get MpReachNLRIAttribute instead of NextHopAttributes
			// TODO: here we only take the first next hop, at some point in the future it would probably be best to
			// consider multiple next hops
			nextHopIP := net.ParseIP(t.NextHops[0])
			if nextHopIP != nil && (nextHopIP.To4() != nil || nextHopIP.To16() != nil) {
				return nextHopIP, nil
			}
			return nil, fmt.Errorf("invalid nextHop address: %s", t.NextHops[0])
		}
	}
	return nil, fmt.Errorf("could not parse next hop received from GoBGP for path: %s", path)
}

// parseBGPPath takes in a GoBGP Path and parses out the destination subnet and the next hop from its attributes.
// If successful, it will return the destination of the BGP path as a subnet form and the next hop. If it
// can't parse the destination or the next hop IP, it returns an error.
func parseBGPPath(path *gobgpapi.Path) (*net.IPNet, net.IP, error) {
	nextHop, err := parseBGPNextHop(path)
	if err != nil {
		return nil, nil, err
	}

	nlri := path.GetNlri()
	var prefix gobgpapi.IPAddressPrefix
	err = nlri.UnmarshalTo(&prefix)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid nlri in advertised path")
	}
	dstSubnet, err := netlink.ParseIPNet(prefix.Prefix + "/" + fmt.Sprint(prefix.PrefixLen))
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't parse IP subnet from nlri advertised path")
	}
	return dstSubnet, nextHop, nil
}

// deleteRoutesByDestination attempts to safely find all routes based upon its destination subnet and delete them
func deleteRoutesByDestination(destinationSubnet *net.IPNet) error {
	routes, err := netlink.RouteListFiltered(nl.FAMILY_ALL, &netlink.Route{
		Dst: destinationSubnet, Protocol: zebraRouteOriginator,
	}, netlink.RT_FILTER_DST|netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return fmt.Errorf("failed to get routes from netlink: %v", err)
	}
	for i, r := range routes {
		klog.V(2).Infof("Found route to remove: %s", r.String())
		if err = netlink.RouteDel(&routes[i]); err != nil {
			return fmt.Errorf("failed to remove route due to %v", err)
		}
	}
	return nil
}

// getPodCIDRsFromAllNodeSources gets the pod CIDRs for all available sources on a given node in a specific order. The
// order of preference is:
//  1. From the kube-router.io/pod-cidr annotation (preserves backwards compatibility)
//  2. From the kube-router.io/pod-cidrs annotation (allows the user to specify multiple CIDRs for a given node which
//     seems to be closer aligned to how upstream is moving)
//  3. From the node's spec definition in node.Spec.PodCIDRs
func getPodCIDRsFromAllNodeSources(node *v1core.Node) (podCIDRs []string) {
	// Prefer kube-router.io/pod-cidr as a matter of keeping backwards compatibility with previous functionality
	podCIDR := node.GetAnnotations()["kube-router.io/pod-cidr"]
	if podCIDR != "" {
		_, _, err := net.ParseCIDR(podCIDR)
		if err != nil {
			klog.Warningf("couldn't parse CIDR %s from kube-router.io/pod-cidr annotation, skipping...", podCIDR)
		} else {
			podCIDRs = append(podCIDRs, podCIDR)
			return podCIDRs
		}
	}

	// Then attempt to find the annotation kube-router.io/pod-cidrs and prefer those second
	cidrsAnnotation := node.GetAnnotations()["kube-router.io/pod-cidrs"]
	if cidrsAnnotation != "" {
		// this should contain comma separated CIDRs, any CIDRs which fail to parse we will emit a warning log for
		// and skip it
		cidrsAnnotArray := strings.Split(cidrsAnnotation, ",")
		for _, cidr := range cidrsAnnotArray {
			_, _, err := net.ParseCIDR(cidr)
			if err != nil {
				klog.Warningf("couldn't parse CIDR %s from kube-router.io/pod-cidrs annotation, skipping...",
					cidr)
				continue
			}
			podCIDRs = append(podCIDRs, cidr)
		}
		return podCIDRs
	}

	// Finally, if all else fails, use the PodCIDRs on the node spec
	return node.Spec.PodCIDRs
}

// getBGPRouteInfoForVIP attempt to automatically find the subnet, BGP AFI/SAFI Family, and nexthop for a given VIP
// based upon whether it is an IPv4 address or an IPv6 address. Returns slash notation subnet as uint32 suitable for
// sending to GoBGP and an error if it is unable to determine the subnet automatically
func (nrc *NetworkRoutingController) getBGPRouteInfoForVIP(vip string) (subnet uint32, nh string,
	afiFamily gobgpapi.Family_Afi, err error) {
	ip := net.ParseIP(vip)
	if ip == nil {
		err = fmt.Errorf("could not parse VIP: %s", vip)
		return
	}
	if ip.To4() != nil {
		subnet = 32
		afiFamily = gobgpapi.Family_AFI_IP
		nhIP := utils.FindBestIPv4NodeAddress(nrc.primaryIP, nrc.nodeIPv4Addrs)
		if nhIP == nil {
			err = fmt.Errorf("could not find an IPv4 address on node to set as nexthop for vip: %s", vip)
		}
		nh = nhIP.String()
		return
	}
	if ip.To16() != nil {
		subnet = 128
		afiFamily = gobgpapi.Family_AFI_IP6
		nhIP := utils.FindBestIPv6NodeAddress(nrc.primaryIP, nrc.nodeIPv6Addrs)
		if nhIP == nil {
			err = fmt.Errorf("could not find an IPv6 address on node to set as nexthop for vip: %s", vip)
		}
		nh = nhIP.String()
		return
	}
	err = fmt.Errorf("could not convert IP to IPv4 or IPv6, unable to find subnet for: %s", vip)
	return
}

// fouPortAndProtoExist checks to see if the given FoU port is already configured on the system via iproute2
// tooling for the given protocol
//
// fou show, shows both IPv4 and IPv6 ports in the same show command, they look like:
// port 5556 gue
// port 5556 gue -6
// where the only thing that distinguishes them is the -6 or not on the end
// WARNING we're parsing a CLI tool here not an API, this may break at some point in the future
func fouPortAndProtoExist(port uint16, isIPv6 bool) bool {
	klog.V(2).Infof("Checking FOU Port and Proto... %d - %t", port, isIPv6)

	fouFamily := netlink.FAMILY_V4
	if isIPv6 {
		fouFamily = netlink.FAMILY_V6
	}
	fous, err := netlink.FouList(fouFamily)
	if err != nil {
		klog.Errorf("failed to list fou ports: %v", err)
		return false
	}

	for _, fou := range fous {
		if fou.Port == int(port) && fou.EncapType == netlink.FOU_ENCAP_GUE {
			return true
		}
	}

	return false
}

// linkFOUEnabled checks to see whether the given link has FoU (Foo over Ethernet) enabled on it, specifically since
// kube-router only works with GUE (Generic UDP Encapsulation) we look for that and not just FoU in general. If the
// linkName is enabled with FoU GUE then we return true, otherwise false
//
// Output for a FoU Enabled GUE tunnel looks like:
// ipip ipip remote <ip> local <ip> dev <dev> ttl 225 pmtudisc encap gue encap-sport auto encap-dport 5555 ...
// Output for a normal IPIP tunnel looks like:
// ipip ipip remote <ip> local <ip> dev <dev> ttl inherit ...
func linkFOUEnabled(linkName string) bool {
	const fouEncapType = "gue"

	nLink, err := netlink.LinkByName(linkName)
	if err != nil {
		klog.Errorf("recevied an error while trying to look at the link details of %s, this shouldn't have happened: "+
			"%v", linkName, err)
		return false

	}

	if nLink.Attrs().EncapType == fouEncapType {
		return true
	}

	return false
}

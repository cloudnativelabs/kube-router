package routing

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	gobgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
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

// generateRouterID will generate a router ID based upon the user's configuration (or lack there of) and the node's
// primary IP address if the user has not specified. If the user has configured the router ID as "generate" then we
// will generate a router ID based upon fnv hashing the node's primary IP address.
func generateRouterID(nodeIPAware utils.NodeIPAware, configRouterID string) (string, error) {
	switch {
	case configRouterID == "generate":
		h := fnv.New32a()
		h.Write(nodeIPAware.GetPrimaryNodeIP())
		hs := h.Sum32()
		gip := make(net.IP, 4)
		binary.BigEndian.PutUint32(gip, hs)
		return gip.String(), nil
	case configRouterID != "":
		return configRouterID, nil
	}

	if nodeIPAware.GetPrimaryNodeIP().To4() == nil {
		return "", errors.New("router-id must be specified when primary node IP is an IPv6 address")
	}
	return configRouterID, nil
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
		nhIP := nrc.krNode.FindBestIPv4NodeAddress()
		if nhIP == nil {
			err = fmt.Errorf("could not find an IPv4 address on node to set as nexthop for vip: %s", vip)
		}
		nh = nhIP.String()
		return
	}
	if ip.To16() != nil {
		subnet = 128
		afiFamily = gobgpapi.Family_AFI_IP6
		nhIP := nrc.krNode.FindBestIPv6NodeAddress()
		if nhIP == nil {
			err = fmt.Errorf("could not find an IPv6 address on node to set as nexthop for vip: %s", vip)
		}
		nh = nhIP.String()
		return
	}
	err = fmt.Errorf("could not convert IP to IPv4 or IPv6, unable to find subnet for: %s", vip)
	return
}

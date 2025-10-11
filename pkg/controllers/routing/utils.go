package routing

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"

	gobgpapi "github.com/osrg/gobgp/v3/api"

	v1core "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
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
	afiFamily gobgpapi.Family_Afi, err error,
) {
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

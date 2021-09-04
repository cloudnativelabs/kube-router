package routing

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/golang/protobuf/ptypes"
	gobgpapi "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/pkg/packet/bgp"
	"github.com/vishvananda/netlink/nl"
	"k8s.io/klog/v2"

	"github.com/vishvananda/netlink"
)

// Used for processing Annotations that may contain multiple items
// Pass this the string and the delimiter
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

func ipv4IsEnabled() bool {
	l, err := net.Listen("tcp4", "")
	if err != nil {
		return false
	}
	_ = l.Close()

	return true
}

func ipv6IsEnabled() bool {
	// If ipv6 is disabled with;
	//
	//  sysctl -w net.ipv6.conf.all.disable_ipv6=1
	//
	// It is still possible to listen on the any-address "::". So this
	// function tries the loopback address "::1" which must be present
	// if ipv6 is enabled.
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	_ = l.Close()

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
// for example, if the node IP is 10.0.0.1 the tunnel interface will be named tun-10001
// Since linux restricts interface names to 15 characters, if length of a node IP
// is greater than 12 (after removing "."), then the interface name is tunXYZ
// as opposed to tun-XYZ
func generateTunnelName(nodeIP string) string {
	hash := strings.ReplaceAll(nodeIP, ".", "")

	if len(hash) < 12 {
		return "tun-" + hash
	}

	return "tun" + hash
}

// validateCommunity takes in a string and attempts to parse a BGP community out of it in a way that is similar to
// gobgp (internal/pkg/table/policy.go:ParseCommunity()). If it is not able to parse the community information it
// returns an error.
func validateCommunity(arg string) error {
	_, err := strconv.ParseUint(arg, 10, 32)
	if err == nil {
		return nil
	}

	_regexpCommunity := regexp.MustCompile(`(\d+):(\d+)`)
	elems := _regexpCommunity.FindStringSubmatch(arg)
	if len(elems) == 3 {
		if _, err := strconv.ParseUint(elems[1], 10, 16); err == nil {
			if _, err = strconv.ParseUint(elems[2], 10, 16); err == nil {
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
		var value ptypes.DynamicAny
		if err := ptypes.UnmarshalAny(pAttr, &value); err != nil {
			return nil, fmt.Errorf("failed to unmarshal path attribute: %s", err)
		}
		// nolint:gocritic // We can't change this to an if condition because it is a .(type) expression
		switch a := value.Message.(type) {
		case *gobgpapi.NextHopAttribute:
			nextHop := net.ParseIP(a.NextHop).To4()
			if nextHop == nil {
				if nextHop = net.ParseIP(a.NextHop).To16(); nextHop == nil {
					return nil, fmt.Errorf("invalid nextHop address: %s", a.NextHop)
				}
			}
			return nextHop, nil
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
	err = ptypes.UnmarshalAny(nlri, &prefix)
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
		Dst: destinationSubnet, Protocol: 0x11,
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

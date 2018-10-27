package routing

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

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
			return nil, fmt.Errorf("Could not parse \"%s\" as an IP", ipString)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func stringSliceToUInt16(s []string) ([]uint16, error) {
	ints := make([]uint16, 0)
	for _, intString := range s {
		newInt, err := strconv.ParseUint(intString, 0, 16)
		if err != nil {
			return nil, fmt.Errorf("Could not parse \"%s\" as an integer", intString)
		}
		ints = append(ints, uint16(newInt))
	}
	return ints, nil
}

func stringSliceToUInt32(s []string) ([]uint32, error) {
	ints := make([]uint32, 0)
	for _, intString := range s {
		newInt, err := strconv.ParseUint(intString, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("Could not parse \"%s\" as an integer", intString)
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
			return nil, fmt.Errorf("Could not parse \"%s\" as a base64 encoded string",
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
	l.Close()

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
	l.Close()

	return true
}

func getNodeSubnet(nodeIp net.IP) (net.IPNet, string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return net.IPNet{}, "", errors.New("Failed to get list of links")
	}
	for _, link := range links {
		addresses, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return net.IPNet{}, "", errors.New("Failed to get list of addr")
		}
		for _, addr := range addresses {
			if addr.IPNet.IP.Equal(nodeIp) {
				return *addr.IPNet, link.Attrs().Name, nil
			}
		}
	}
	return net.IPNet{}, "", errors.New("Failed to find interface with specified node ip")
}

// generateTunnelName will generate a name for a tunnel interface given a node IP
// for example, if the node IP is 10.0.0.1 the tunnel interface will be named tun-10001
// Since linux restricts interface names to 15 characters, if length of a node IP
// is greater than 12 (after removing "."), then the interface name is tunXYZ
// as opposed to tun-XYZ
func generateTunnelName(nodeIP string) string {
	hash := strings.Replace(nodeIP, ".", "", -1)

	if len(hash) < 12 {
		return "tun-" + hash
	}

	return "tun" + hash
}

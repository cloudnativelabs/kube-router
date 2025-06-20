package utils

import (
	"bytes"
	"fmt"
	"net"
)

const (
	IPv4DefaultRoute = "0.0.0.0/0"
	IPv6DefaultRoute = "::/0"

	ipv4NetMaskBits = 32
	ipv6NetMaskBits = 128
)

// GetSingleIPNet returns an IPNet object that represents a subnet containing a single IP address for a given IP address
// with proper handling for IPv4 and IPv6 addresses.
func GetSingleIPNet(ip net.IP) *net.IPNet {
	if ip.To4() != nil {
		return &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(ipv4NetMaskBits, ipv4NetMaskBits),
		}
	} else {
		return &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(ipv6NetMaskBits, ipv6NetMaskBits),
		}
	}
}

// GetIPv4NetMaxMaskBits returns the maximum mask bits for an IPv4 address
func GetIPv4NetMaxMaskBits() uint32 {
	return ipv4NetMaskBits
}

// GetIPv6NetMaxMaskBits returns the maximum mask bits for an IPv6 address
func GetIPv6NetMaxMaskBits() uint32 {
	return ipv6NetMaskBits
}

// ContainsIPv4Address checks a given string array to see if it contains a valid IPv4 address within it
func ContainsIPv4Address(addrs []string) bool {
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			return true
		}
	}
	return false
}

// ContainsIPv6Address checks a given string array to see if it contains a valid IPv6 address within it
func ContainsIPv6Address(addrs []string) bool {
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			continue
		}
		if ip.To16() != nil {
			return true
		}
	}
	return false
}

// GetDefaultIPv4Route returns the default IPv4 route
func GetDefaultIPv4Route() *net.IPNet {
	_, defaultPrefixCIDR, err := net.ParseCIDR(IPv4DefaultRoute)
	if err != nil {
		return nil
	}
	return defaultPrefixCIDR
}

// GetDefaultIPv6Route returns the default IPv6 route
func GetDefaultIPv6Route() *net.IPNet {
	_, defaultPrefixCIDR, err := net.ParseCIDR(IPv6DefaultRoute)
	if err != nil {
		return nil
	}
	return defaultPrefixCIDR
}

// IPNetEqual checks if two IPNet objects are equal by comparing the IP and Mask
func IPNetEqual(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.IP.Equal(b.IP) && bytes.Equal(a.Mask, b.Mask)
}

// IsDefaultRoute checks if a given CIDR is a default route by comparing it to the default routes for IPv4 and IPv6
func IsDefaultRoute(cidr *net.IPNet) (bool, error) {
	var defaultPrefixCIDR *net.IPNet
	var err error

	if cidr.IP.To4() != nil {
		_, defaultPrefixCIDR, err = net.ParseCIDR(IPv4DefaultRoute)
		if err != nil {
			return false, fmt.Errorf("failed to parse default route: %s", err.Error())
		}
	} else {
		_, defaultPrefixCIDR, err = net.ParseCIDR(IPv6DefaultRoute)
		if err != nil {
			return false, fmt.Errorf("failed to parse default route: %s", err.Error())
		}
	}
	return IPNetEqual(defaultPrefixCIDR, cidr), nil
}

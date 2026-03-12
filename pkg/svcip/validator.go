package svcip

import (
	"fmt"
	"net"

	v1core "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
)

// Config holds the raw CIDR strings and feature flags needed to construct a Validator.
type Config struct {
	ExternalIPCIDRs   []string
	LoadBalancerCIDRs []string
	ClusterIPCIDRs    []string
	StrictValidation  bool
	EnableIPv4        bool
	EnableIPv6        bool
}

// RangeQuerier provides read access to parsed CIDR ranges, optionally filtered by IP family.
// Calling with no families returns all ranges. Calling with one or more families returns only
// ranges matching those families.
type RangeQuerier interface {
	ExternalIPRanges(families ...v1core.IPFamily) []net.IPNet
	LoadBalancerIPRanges(families ...v1core.IPFamily) []net.IPNet
	ClusterIPRanges(families ...v1core.IPFamily) []net.IPNet
}

// Filter validates individual service IPs against configured CIDR ranges and strict mode settings.
type Filter interface {
	FilterExternalIPs(ips []string, svcName, svcNamespace string) []string
	FilterLoadBalancerIPs(ips []string, svcName, svcNamespace string) []string
}

// Validator implements both RangeQuerier and Filter. It parses all CIDRs once at construction time,
// classifies them by IP family, and validates them against the enabled protocol configuration.
type Validator struct {
	externalIPv4Ranges     []net.IPNet
	externalIPv6Ranges     []net.IPNet
	loadBalancerIPv4Ranges []net.IPNet
	loadBalancerIPv6Ranges []net.IPNet
	clusterIPv4Ranges      []net.IPNet
	clusterIPv6Ranges      []net.IPNet
	strictValidation       bool
}

const maxClusterIPCIDRs = 2

// NewValidator parses all CIDR strings, classifies them by IP family, and validates that
// each CIDR's family matches the enabled protocol configuration. It returns an error if any
// CIDR string is invalid, if a CIDR's family conflicts with the enabled protocols, or if
// ClusterIP CIDR constraints are violated (must be non-empty, max 2).
func NewValidator(cfg Config) (*Validator, error) {
	v := &Validator{
		strictValidation: cfg.StrictValidation,
	}

	var err error

	v.externalIPv4Ranges, v.externalIPv6Ranges, err = parseCIDRsByFamily(
		cfg.ExternalIPCIDRs, cfg.EnableIPv4, cfg.EnableIPv6, "--service-external-ip-range")
	if err != nil {
		return nil, err
	}

	v.loadBalancerIPv4Ranges, v.loadBalancerIPv6Ranges, err = parseCIDRsByFamily(
		cfg.LoadBalancerCIDRs, cfg.EnableIPv4, cfg.EnableIPv6, "--loadbalancer-ip-range")
	if err != nil {
		return nil, err
	}

	v.clusterIPv4Ranges, v.clusterIPv6Ranges, err = parseCIDRsByFamily(
		cfg.ClusterIPCIDRs, cfg.EnableIPv4, cfg.EnableIPv6, "--service-cluster-ip-range")
	if err != nil {
		return nil, err
	}

	if len(cfg.ClusterIPCIDRs) == 0 {
		return nil, fmt.Errorf("failed to parse %s parameter: the list is empty",
			"--service-cluster-ip-range")
	}
	if len(cfg.ClusterIPCIDRs) > maxClusterIPCIDRs {
		return nil, fmt.Errorf("too many CIDRs provided in %s parameter, only two "+
			"addresses are allowed at once for dual-stack", "--service-cluster-ip-range")
	}

	return v, nil
}

// parseCIDRsByFamily parses a list of CIDR strings and classifies them into IPv4 and IPv6 buckets.
// It returns an error if any CIDR is invalid or if a CIDR's family conflicts with the enabled
// protocol configuration.
func parseCIDRsByFamily(cidrs []string, enableIPv4, enableIPv6 bool,
	flagName string) (ipv4, ipv6 []net.IPNet, err error) {

	for _, cidrStr := range cidrs {
		ip, ipnet, parseErr := net.ParseCIDR(cidrStr)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("failed to parse %s parameter: '%s': %v",
				flagName, cidrStr, parseErr)
		}

		if ip.To4() != nil {
			if !enableIPv4 {
				return nil, nil, fmt.Errorf("IPv4 CIDR %s specified in %s while IPv4 is disabled",
					cidrStr, flagName)
			}
			ipv4 = append(ipv4, *ipnet)
		} else {
			if !enableIPv6 {
				return nil, nil, fmt.Errorf("IPv6 CIDR %s specified in %s while IPv6 is disabled",
					cidrStr, flagName)
			}
			ipv6 = append(ipv6, *ipnet)
		}
	}

	return ipv4, ipv6, nil
}

// rangesForFamilies returns the combined ranges for the requested families. If no families are
// specified, all ranges are returned.
func rangesForFamilies(ipv4, ipv6 []net.IPNet, families []v1core.IPFamily) []net.IPNet {
	if len(families) == 0 {
		result := make([]net.IPNet, 0, len(ipv4)+len(ipv6))
		result = append(result, ipv4...)
		result = append(result, ipv6...)
		return result
	}

	result := make([]net.IPNet, 0)
	for _, family := range families {
		switch family {
		case v1core.IPv4Protocol:
			result = append(result, ipv4...)
		case v1core.IPv6Protocol:
			result = append(result, ipv6...)
		case v1core.IPFamilyUnknown:
			// Unknown family — skip silently
		}
	}
	return result
}

// ExternalIPRanges returns the parsed ExternalIP CIDR ranges, optionally filtered by IP family.
func (v *Validator) ExternalIPRanges(families ...v1core.IPFamily) []net.IPNet {
	return rangesForFamilies(v.externalIPv4Ranges, v.externalIPv6Ranges, families)
}

// LoadBalancerIPRanges returns the parsed LoadBalancerIP CIDR ranges, optionally filtered by family.
func (v *Validator) LoadBalancerIPRanges(families ...v1core.IPFamily) []net.IPNet {
	return rangesForFamilies(v.loadBalancerIPv4Ranges, v.loadBalancerIPv6Ranges, families)
}

// ClusterIPRanges returns the parsed ClusterIP CIDR ranges, optionally filtered by IP family.
func (v *Validator) ClusterIPRanges(families ...v1core.IPFamily) []net.IPNet {
	return rangesForFamilies(v.clusterIPv4Ranges, v.clusterIPv6Ranges, families)
}

// LogStatus logs the current strict IP validation configuration at startup.
func (v *Validator) LogStatus() {
	if !v.strictValidation {
		klog.Infof("Strict external IP validation is disabled, all externalIPs and " +
			"loadBalancerIPs will be accepted")
		return
	}

	klog.Infof("Strict external IP validation is enabled")

	externalRanges := v.ExternalIPRanges()
	if len(externalRanges) == 0 {
		klog.Warningf("No --service-external-ip-range configured: all externalIPs will be " +
			"rejected in strict mode")
	} else {
		for _, cidr := range externalRanges {
			klog.Infof("Allowed externalIP range: %s", cidr.String())
		}
	}

	lbRanges := v.LoadBalancerIPRanges()
	if len(lbRanges) == 0 {
		klog.Warningf("No --loadbalancer-ip-range configured: all loadBalancerIPs will be " +
			"rejected in strict mode")
	} else {
		for _, cidr := range lbRanges {
			klog.Infof("Allowed loadBalancerIP range: %s", cidr.String())
		}
	}
}

// FilterExternalIPs validates externalIPs against configured CIDR ranges and ClusterIP ranges.
// When strict mode is enabled and no ranges are configured, all IPs are rejected (default-deny).
// When strict mode is disabled, all IPs pass through unfiltered.
func (v *Validator) FilterExternalIPs(ips []string, svcName, svcNamespace string) []string {
	if !v.strictValidation {
		return ips
	}

	externalRanges := v.ExternalIPRanges()
	if len(externalRanges) == 0 {
		if len(ips) > 0 {
			klog.Warningf("Service %s/%s: rejecting all %d externalIPs because no "+
				"--service-external-ip-range is configured (strict mode default-deny)",
				svcNamespace, svcName, len(ips))
		}
		return nil
	}

	clusterRanges := v.ClusterIPRanges()
	filtered := make([]string, 0, len(ips))
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			klog.Warningf("Service %s/%s: rejecting externalIP %q: not a valid IP address",
				svcNamespace, svcName, ipStr)
			continue
		}
		if utils.IsIPInRanges(ip, clusterRanges) {
			klog.Warningf("Service %s/%s: rejecting externalIP %s: conflicts with "+
				"cluster IP range", svcNamespace, svcName, ipStr)
			continue
		}
		if !utils.IsIPInRanges(ip, externalRanges) {
			klog.Warningf("Service %s/%s: rejecting externalIP %s: not within any "+
				"configured --service-external-ip-range",
				svcNamespace, svcName, ipStr)
			continue
		}
		filtered = append(filtered, ipStr)
	}
	return filtered
}

// FilterLoadBalancerIPs validates loadBalancerIPs against configured CIDR ranges and ClusterIP
// ranges. When strict mode is enabled and no ranges are configured, all IPs are rejected
// (default-deny). When strict mode is disabled, all IPs pass through unfiltered.
func (v *Validator) FilterLoadBalancerIPs(ips []string, svcName, svcNamespace string) []string {
	if !v.strictValidation {
		return ips
	}

	lbRanges := v.LoadBalancerIPRanges()
	if len(lbRanges) == 0 {
		if len(ips) > 0 {
			klog.Warningf("Service %s/%s: rejecting all %d loadBalancerIPs because no "+
				"--loadbalancer-ip-range is configured (strict mode default-deny)",
				svcNamespace, svcName, len(ips))
		}
		return nil
	}

	clusterRanges := v.ClusterIPRanges()
	filtered := make([]string, 0, len(ips))
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			klog.Warningf("Service %s/%s: rejecting loadBalancerIP %q: not a valid "+
				"IP address", svcNamespace, svcName, ipStr)
			continue
		}
		if utils.IsIPInRanges(ip, clusterRanges) {
			klog.Warningf("Service %s/%s: rejecting loadBalancerIP %s: conflicts with "+
				"cluster IP range", svcNamespace, svcName, ipStr)
			continue
		}
		if !utils.IsIPInRanges(ip, lbRanges) {
			klog.Warningf("Service %s/%s: rejecting loadBalancerIP %s: not within any "+
				"configured --loadbalancer-ip-range",
				svcNamespace, svcName, ipStr)
			continue
		}
		filtered = append(filtered, ipStr)
	}
	return filtered
}

package routing

import (
	"fmt"
	"net"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/vishvananda/netlink"
)

const (
	PBRRuleAdd = iota
	PBRRuleDel
)

// ipRuleAbstraction used for abstracting iproute2 rule additions between IPv4 and IPv6 for both add and del operations.
// ipProtocol is the iproute2 protocol specified as a string ("-4" or "-6"). ipOp is the rule operation specified as a
// string ("add" or "del). The cidr is the IPv4 / IPv6 source CIDR string that when received will be used to lookup
// routes in a custom table.
func ipRuleAbstraction(ipFamily int, ipOp int, cidr string) error {
	_, nSrc, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("failed to parse CIDR: %s", err.Error())
	}

	nRule := &netlink.Rule{
		Family: ipFamily,
		Src:    nSrc,
		Table:  customRouteTableID,
	}
	rules, err := netlink.RuleListFiltered(ipFamily, nRule, netlink.RT_FILTER_SRC)
	if err != nil {
		return fmt.Errorf("failed to list rules: %s", err.Error())
	}

	if ipOp == PBRRuleDel && len(rules) > 0 {
		if err := netlink.RuleDel(nRule); err != nil {
			return fmt.Errorf("failed to delete rule: %s", err.Error())
		}
	} else if ipOp == PBRRuleAdd && len(rules) < 1 {
		if err := netlink.RuleAdd(nRule); err != nil {
			return fmt.Errorf("failed to add rule: %s", err.Error())
		}
	}

	return nil
}

// setup a custom routing table that will be used for policy based routing to ensure traffic originating
// on tunnel interface only leaves through tunnel interface irrespective rp_filter enabled/disabled
func (nrc *NetworkRoutingController) enablePolicyBasedRouting() error {
	err := utils.RouteTableAdd(customRouteTableID, customRouteTableName)
	if err != nil {
		return fmt.Errorf("failed to update rt_tables file: %s", err)
	}

	if nrc.isIPv4Capable {
		for _, ipv4CIDR := range nrc.podIPv4CIDRs {
			if err := ipRuleAbstraction(netlink.FAMILY_V4, PBRRuleAdd, ipv4CIDR); err != nil {
				return err
			}
		}
	}
	if nrc.isIPv6Capable {
		for _, ipv6CIDR := range nrc.podIPv6CIDRs {
			if err := ipRuleAbstraction(netlink.FAMILY_V6, PBRRuleAdd, ipv6CIDR); err != nil {
				return err
			}
		}
	}

	return nil
}

func (nrc *NetworkRoutingController) disablePolicyBasedRouting() error {
	err := utils.RouteTableAdd(customRouteTableID, customRouteTableName)
	if err != nil {
		return fmt.Errorf("failed to update rt_tables file: %s", err)
	}

	if nrc.isIPv4Capable {
		for _, ipv4CIDR := range nrc.podIPv4CIDRs {
			if err := ipRuleAbstraction(netlink.FAMILY_V4, PBRRuleDel, ipv4CIDR); err != nil {
				return err
			}
		}
	}
	if nrc.isIPv6Capable {
		for _, ipv6CIDR := range nrc.podIPv6CIDRs {
			if err := ipRuleAbstraction(netlink.FAMILY_V6, PBRRuleDel, ipv6CIDR); err != nil {
				return err
			}
		}
	}

	return nil
}

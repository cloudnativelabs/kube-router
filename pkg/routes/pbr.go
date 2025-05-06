package routes

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

const (
	// CustomTableID is the ID of the custom, iproute2 routing table that will be used for policy based routing
	CustomTableID = 77
	// CustomTableName is the name of the custom, iproute2 routing table that will be used for policy based routing
	CustomTableName = "kube-router"
)

// PolicyBasedRules is a struct that holds all of the information needed for manipulating policy based routing rules
type PolicyBasedRules struct {
	nfa          utils.NodeFamilyAware
	podIPv4CIDRs []string
	podIPv6CIDRs []string
}

// NewPolicyBasedRules creates a new PBR object which will be used to manipulate policy based routing rules
func NewPolicyBasedRules(nfa utils.NodeFamilyAware, podIPv4CIDRs, podIPv6CIDRs []string) *PolicyBasedRules {
	return &PolicyBasedRules{
		nfa:          nfa,
		podIPv4CIDRs: podIPv4CIDRs,
		podIPv6CIDRs: podIPv6CIDRs,
	}
}

// ipRuleAbstraction used for abstracting iproute2 rule additions between IPv4 and IPv6 for both add and del operations.
// ipProtocol is the iproute2 protocol specified as a string ("-4" or "-6"). ipOp is the rule operation specified as a
// string ("add" or "del). The cidr is the IPv4 / IPv6 source CIDR string that when received will be used to lookup
// routes in a custom table.
func ipRuleAbstraction(ipFamily int, ipOp int, cidr string) error {
	_, nSrc, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("failed to parse CIDR: %s", err.Error())
	}

	nRule := netlink.NewRule()
	nRule.Family = ipFamily
	nRule.Src = nSrc
	nRule.Table = CustomTableID

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

// Enable setup a custom routing table that will be used for policy based routing to ensure traffic
// originating on tunnel interface only leaves through tunnel interface irrespective rp_filter enabled/disabled
func (pbr *PolicyBasedRules) Enable() error {
	err := utils.RouteTableAdd(CustomTableID, CustomTableName)
	if err != nil {
		return fmt.Errorf("failed to update rt_tables file: %s", err)
	}

	if pbr.nfa.IsIPv4Capable() {
		for _, ipv4CIDR := range pbr.podIPv4CIDRs {
			if err := ipRuleAbstraction(netlink.FAMILY_V4, PBRRuleAdd, ipv4CIDR); err != nil {
				return err
			}
		}
	}
	if pbr.nfa.IsIPv6Capable() {
		for _, ipv6CIDR := range pbr.podIPv6CIDRs {
			if err := ipRuleAbstraction(netlink.FAMILY_V6, PBRRuleAdd, ipv6CIDR); err != nil {
				return err
			}
		}
	}

	return nil
}

// Disable removes the custom routing table that was used for policy based routing
func (pbr *PolicyBasedRules) Disable() error {
	err := utils.RouteTableAdd(CustomTableID, CustomTableName)
	if err != nil {
		return fmt.Errorf("failed to update rt_tables file: %s", err)
	}

	if pbr.nfa.IsIPv4Capable() {
		for _, ipv4CIDR := range pbr.podIPv4CIDRs {
			if err := ipRuleAbstraction(netlink.FAMILY_V4, PBRRuleDel, ipv4CIDR); err != nil {
				return err
			}
		}
	}
	if pbr.nfa.IsIPv6Capable() {
		for _, ipv6CIDR := range pbr.podIPv6CIDRs {
			if err := ipRuleAbstraction(netlink.FAMILY_V6, PBRRuleDel, ipv6CIDR); err != nil {
				return err
			}
		}
	}

	return nil
}

package routes

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
)

const (
	// CustomTableID is the ID of the custom, iproute2 routing table that will be used for policy based routing
	CustomTableID = "77"
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
func ipRuleAbstraction(ipProtocol, ipOp, cidr string) error {
	out, err := exec.Command("ip", ipProtocol, "rule", "list").Output()
	if err != nil {
		return fmt.Errorf("failed to verify if `ip rule` exists: %s", err.Error())
	}

	if strings.Contains(string(out), cidr) && ipOp == "del" {
		err = exec.Command("ip", ipProtocol, "rule", ipOp, "from", cidr, "lookup", CustomTableID).Run()
		if err != nil {
			return fmt.Errorf("failed to add ip rule due to: %s", err.Error())
		}
	} else if !strings.Contains(string(out), cidr) && ipOp == "add" {
		err = exec.Command("ip", ipProtocol, "rule", ipOp, "from", cidr, "lookup", CustomTableID).Run()
		if err != nil {
			return fmt.Errorf("failed to add ip rule due to: %s", err.Error())
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
			if err := ipRuleAbstraction("-4", "add", ipv4CIDR); err != nil {
				return err
			}
		}
	}
	if pbr.nfa.IsIPv6Capable() {
		for _, ipv6CIDR := range pbr.podIPv6CIDRs {
			if err := ipRuleAbstraction("-6", "add", ipv6CIDR); err != nil {
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
			if err := ipRuleAbstraction("-4", "del", ipv4CIDR); err != nil {
				return err
			}
		}
	}
	if pbr.nfa.IsIPv6Capable() {
		for _, ipv6CIDR := range pbr.podIPv6CIDRs {
			if err := ipRuleAbstraction("-6", "del", ipv6CIDR); err != nil {
				return err
			}
		}
	}

	return nil
}

package routing

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
)

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
		err = exec.Command("ip", ipProtocol, "rule", ipOp, "from", cidr, "lookup", customRouteTableID).Run()
		if err != nil {
			return fmt.Errorf("failed to add ip rule due to: %s", err.Error())
		}
	} else if !strings.Contains(string(out), cidr) && ipOp == "add" {
		err = exec.Command("ip", ipProtocol, "rule", ipOp, "from", cidr, "lookup", customRouteTableID).Run()
		if err != nil {
			return fmt.Errorf("failed to add ip rule due to: %s", err.Error())
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
			if err := ipRuleAbstraction("-4", "add", ipv4CIDR); err != nil {
				return err
			}
		}
	}
	if nrc.isIPv6Capable {
		for _, ipv6CIDR := range nrc.podIPv6CIDRs {
			if err := ipRuleAbstraction("-6", "add", ipv6CIDR); err != nil {
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
			if err := ipRuleAbstraction("-4", "del", ipv4CIDR); err != nil {
				return err
			}
		}
	}
	if nrc.isIPv6Capable {
		for _, ipv6CIDR := range nrc.podIPv6CIDRs {
			if err := ipRuleAbstraction("-6", "del", ipv6CIDR); err != nil {
				return err
			}
		}
	}

	return nil
}

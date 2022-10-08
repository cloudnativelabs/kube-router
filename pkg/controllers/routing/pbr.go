package routing

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cloudnativelabs/kube-router/pkg/utils"
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
	err := rtTablesAdd(customRouteTableID, customRouteTableName)
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
	err := rtTablesAdd(customRouteTableID, customRouteTableName)
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

func rtTablesAdd(tableNumber, tableName string) error {
	b, err := os.ReadFile("/etc/iproute2/rt_tables")
	if err != nil {
		return fmt.Errorf("failed to read: %s", err.Error())
	}

	if !strings.Contains(string(b), tableName) {
		f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("failed to open: %s", err.Error())
		}
		defer utils.CloseCloserDisregardError(f)
		if _, err = f.WriteString(tableNumber + " " + tableName + "\n"); err != nil {
			return fmt.Errorf("failed to write: %s", err.Error())
		}
	}

	return nil
}

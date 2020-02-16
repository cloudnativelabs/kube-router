package routing

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

// setup a custom routing table that will be used for policy based routing to ensure traffic originating
// on tunnel interface only leaves through tunnel interface irrespective rp_filter enabled/disabled
func (nrc *NetworkRoutingController) enablePolicyBasedRouting() error {
	err := rtTablesAdd(customRouteTableID, customRouteTableName)
	if err != nil {
		return fmt.Errorf("Failed to update rt_tables file: %s", err)
	}

	out, err := exec.Command("ip", "rule", "list").Output()
	if err != nil {
		return fmt.Errorf("Failed to verify if `ip rule` exists: %s", err.Error())
	}

	if !strings.Contains(string(out), nrc.podCidr) {
		err = exec.Command("ip", "rule", "add", "from", nrc.podCidr, "lookup", customRouteTableID).Run()
		if err != nil {
			return fmt.Errorf("Failed to add ip rule due to: %s", err.Error())
		}
	}

	return nil
}

func (nrc *NetworkRoutingController) disablePolicyBasedRouting() error {
	err := rtTablesAdd(customRouteTableID, customRouteTableName)
	if err != nil {
		return fmt.Errorf("Failed to update rt_tables file: %s", err)
	}

	out, err := exec.Command("ip", "rule", "list").Output()
	if err != nil {
		return fmt.Errorf("Failed to verify if `ip rule` exists: %s",
			err.Error())
	}

	if strings.Contains(string(out), nrc.podCidr) {
		err = exec.Command("ip", "rule", "del", "from", nrc.podCidr, "table", customRouteTableID).Run()
		if err != nil {
			return fmt.Errorf("Failed to delete ip rule: %s", err.Error())
		}
	}

	return nil
}

func rtTablesAdd(tableNumber, tableName string) error {
	b, err := ioutil.ReadFile("/etc/iproute2/rt_tables")
	if err != nil {
		return fmt.Errorf("Failed to read: %s", err.Error())
	}

	if !strings.Contains(string(b), tableName) {
		f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("Failed to open: %s", err.Error())
		}
		defer f.Close()
		if _, err = f.WriteString(tableNumber + " " + tableName + "\n"); err != nil {
			return fmt.Errorf("Failed to write: %s", err.Error())
		}
	}

	return nil
}

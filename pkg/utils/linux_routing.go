package utils

import (
	"fmt"
	"os"
	"strings"

	"k8s.io/klog/v2"
)

const (
	rtTablesFileName = "rt_tables"
	iproutePkg       = "iproute2"
)

var (
	rtTablesPosLoc = []string{
		fmt.Sprintf("/etc/%s/%s", iproutePkg, rtTablesFileName),
		fmt.Sprintf("/usr/lib/%s/%s", iproutePkg, rtTablesFileName),
		fmt.Sprintf("/usr/share/%s/%s", iproutePkg, rtTablesFileName),
	}
)

// RouteTableAdd adds a new named table to iproute's rt_tables configuration file
func RouteTableAdd(tableNumber, tableName string) error {
	var rtTablesLoc string
	for _, possibleLoc := range rtTablesPosLoc {
		_, err := os.Stat(possibleLoc)
		if err != nil {
			klog.V(2).Infof("Did not find iproute2's rt_tables in location %s", possibleLoc)
			continue
		}
		rtTablesLoc = possibleLoc
	}
	if rtTablesLoc == "" {
		return fmt.Errorf("did not find rt_tables in any of the expected locations: %s", rtTablesFileName)
	}

	b, err := os.ReadFile(rtTablesLoc)
	if err != nil {
		return fmt.Errorf("failed to read: %s", err.Error())
	}

	if !strings.Contains(string(b), tableName) {
		f, err := os.OpenFile(rtTablesLoc, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("failed to open: %s", err.Error())
		}
		defer CloseCloserDisregardError(f)
		if _, err = f.WriteString(tableNumber + " " + tableName + "\n"); err != nil {
			return fmt.Errorf("failed to write: %s", err.Error())
		}
	}

	return nil
}

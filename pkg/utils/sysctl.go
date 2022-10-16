package utils

import (
	"fmt"
	"os"
	"strconv"
)

const (
	// Network Services Configuration Paths
	IPv4IPVSConntrack        = "net/ipv4/vs/conntrack"
	IPv4IPVSExpireNodestConn = "net/ipv4/vs/expire_nodest_conn"
	IPv4IPVSExpireQuiescent  = "net/ipv4/vs/expire_quiescent_template"
	IPv4IPVSConnReuseMode    = "net/ipv4/vs/conn_reuse_mode"
	IPv4ConfAllArpIgnore     = "net/ipv4/conf/all/arp_ignore"
	IPv4ConfAllArpAnnounce   = "net/ipv4/conf/all/arp_announce"

	// Network Routes Configuration Paths
	BridgeNFCallIPTables  = "net/bridge/bridge-nf-call-iptables"
	BridgeNFCallIP6Tables = "net/bridge/bridge-nf-call-ip6tables"

	// Template Configuration Paths
	IPv4ConfRPFilterTemplate = "net/ipv4/conf/%s/rp_filter"
)

type SysctlError struct {
	additionalInfo string
	err            error
	option         string
	value          int
	fatal          bool
}

// Error return the error as string
func (e *SysctlError) Error() string {
	return fmt.Sprintf("Sysctl %s=%d : %s (%s)", e.option, e.value, e.err, e.additionalInfo)
}

// IsFatal was the error fatal and reason to exit kube-router
func (e *SysctlError) IsFatal() bool {
	return e.fatal
}

// Unwrap allows us to unwrap an error showing the original error
func (e *SysctlError) Unwrap() error {
	return e.err
}

// SetSysctlSingleTemplate sets a sysctl value by first formatting the PathTemplate parameter with the substitute string
// and then setting the sysctl to the value parameter
func SetSysctlSingleTemplate(pathTemplate string, substitute string, value int) *SysctlError {
	actualPath := fmt.Sprintf(pathTemplate, substitute)
	return SetSysctl(actualPath, value)
}

// SetSysctl sets a sysctl value
func SetSysctl(path string, value int) *SysctlError {
	sysctlPath := fmt.Sprintf("/proc/sys/%s", path)
	if _, err := os.Stat(sysctlPath); err != nil {
		if os.IsNotExist(err) {
			return &SysctlError{
				"option not found, Does your kernel version support this feature?",
				err, path, value, false}
		}
		return &SysctlError{"path existed, but could not be stat'd", err, path, value, true}
	}
	err := os.WriteFile(sysctlPath, []byte(strconv.Itoa(value)), 0640)
	if err != nil {
		return &SysctlError{"path could not be set", err, path, value, true}
	}
	return nil
}

package utils

import (
	"fmt"
	"os"
	"strconv"
)

const (
	// From what I can see there are no IPv6 equivalents for the below options, so we only consider IPv6 here
	// Network Services Configuration Paths
	IPv4IPVSConntrack        = "net/ipv4/vs/conntrack"
	IPv4IPVSExpireNodestConn = "net/ipv4/vs/expire_nodest_conn"
	IPv4IPVSExpireQuiescent  = "net/ipv4/vs/expire_quiescent_template"
	IPv4IPVSConnReuseMode    = "net/ipv4/vs/conn_reuse_mode"
	IPv4IPVSSloppyTCP        = "net/ipv4/vs/sloppy_tcp"
	IPv4ConfAllArpIgnore     = "net/ipv4/conf/all/arp_ignore"
	IPv4ConfAllArpAnnounce   = "net/ipv4/conf/all/arp_announce"
	IPv6ConfAllDisableIPv6   = "net/ipv6/conf/all/disable_ipv6"

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
	hasValue       bool
	value          int
	fatal          bool
}

// Error return the error as string
func (e *SysctlError) Error() string {
	value := ""
	if e.hasValue {
		value = fmt.Sprintf("=%d", e.value)
	}
	return fmt.Sprintf("Sysctl %s%s : %s (%s)", e.option, value, e.err, e.additionalInfo)
}

// IsFatal was the error fatal and reason to exit kube-router
func (e *SysctlError) IsFatal() bool {
	return e.fatal
}

// Unwrap allows us to unwrap an error showing the original error
func (e *SysctlError) Unwrap() error {
	return e.err
}

type SysctlConfig struct {
	name  string
	value int8
}

func (n *SysctlConfig) CachedVal() int {
	return int(n.value)
}

func (n *SysctlConfig) WriteVal(val int) *SysctlError {
	err := SetSysctl(n.name, val)
	if err != nil {
		return err
	}
	n.value = int8(val)
	return nil
}

func sysctlStat(path string, hasValue bool, value int) (string, *SysctlError) {
	sysctlPath := fmt.Sprintf("/proc/sys/%s", path)
	if _, err := os.Stat(sysctlPath); err != nil {
		if os.IsNotExist(err) {
			return sysctlPath, &SysctlError{
				"option not found, Does your kernel version support this feature?",
				err, path, hasValue, value, false}
		}
		return sysctlPath, &SysctlError{"path existed, but could not be stat'd", err, path, hasValue, value, true}
	}
	return sysctlPath, nil
}

// GetSysctlSingleTemplate gets a sysctl value by first formatting the PathTemplate parameter with the substitute string
// and then getting the sysctl value and converting it into a string
func GetSysctlSingleTemplate(pathTemplate string, substitute string) (string, *SysctlError) {
	actualPath := fmt.Sprintf(pathTemplate, substitute)
	return GetSysctl(actualPath)
}

// GetSysctl gets a sysctl value
func GetSysctl(path string) (string, *SysctlError) {
	sysctlPath, err := sysctlStat(path, false, 0)
	if err != nil {
		return "", err
	}
	buf, readErr := os.ReadFile(sysctlPath)
	if readErr != nil {
		return "", &SysctlError{"path could not be read", err, path, false, 0, true}
	}
	return string(buf), nil
}

// SetSysctlSingleTemplate sets a sysctl value by first formatting the PathTemplate parameter with the substitute string
// and then setting the sysctl to the value parameter
func SetSysctlSingleTemplate(pathTemplate string, substitute string, value int) *SysctlError {
	actualPath := fmt.Sprintf(pathTemplate, substitute)
	return SetSysctl(actualPath, value)
}

// SetSysctl sets a sysctl value
func SetSysctl(path string, value int) *SysctlError {
	sysctlPath, err := sysctlStat(path, true, value)
	if err != nil {
		return err
	}
	writeErr := os.WriteFile(sysctlPath, []byte(strconv.Itoa(value)), 0640)
	if writeErr != nil {
		return &SysctlError{"path could not be set", err, path, true, value, true}
	}
	return nil
}

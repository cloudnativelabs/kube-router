package utils

import (
	"fmt"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/plugins/ipam/host-local/backend/allocator"
)

func GetPodCidrDetails(cniConfFilePath string) (string, int, error) {
	netconfig, err := libcni.ConfFromFile(cniConfFilePath)
	if err != nil {
		return "", 0, fmt.Errorf("Failed to load CNI conf: %s", err.Error())
	}

	var ipamConfig *allocator.IPAMConfig
	ipamConfig, _, err = allocator.LoadIPAMConfig(netconfig.Bytes, "")
	if err != nil {
		return "", 0, fmt.Errorf("Failed to get IPAM details from the CNI conf file: %s", err.Error())
	}

	cidrlen, _ := ipamConfig.Subnet.Mask.Size()
	return ipamConfig.Subnet.IP.String(), cidrlen, nil
}

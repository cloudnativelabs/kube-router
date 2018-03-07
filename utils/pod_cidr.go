package utils

import (
	"fmt"
	"net"
	"strings"
	"github.com/golang/glog"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"k8s.io/client-go/kubernetes"
)

// GetPodCidrFromCniSpec gets pod CIDR allocated to the node from CNI spec file and returns it
func GetPodCidrFromCniSpec(cniConfFilePath string) (net.IPNet, error) {
	netconfig, err := libcni.ConfFromFile(cniConfFilePath)

	if err != nil {
		return net.IPNet{}, fmt.Errorf("Failed to load CNI conf file: %s", err.Error())
	}

	var ipamConfig *allocator.IPAMConfig
	ipamConfig, version, err := allocator.LoadIPAMConfig(netconfig.Bytes, "")

	if err != nil {
		return net.IPNet{}, fmt.Errorf("Failed to get IPAM details from the CNI conf file: %s", err.Error())
	}

	// find ipv4 configured range
	for _, rs := range ipamConfig.Ranges {
		for _, r := range rs {
			ipnet := net.IPNet(r.Subnet)

			// stupid IPV4 detection
			if strings.Contains(ipnet.String(), ".") {
				return ipnet, nil
			}
		}
	}

	return net.IPNet{}, fmt.Errorf("Failed to find a ipv4 address")
}

// GetPodCidrFromNodeSpec reads the pod CIDR allocated to the node from API node object and returns it
func GetPodCidrFromNodeSpec(clientset *kubernetes.Clientset, hostnameOverride string) (string, error) {
	node, err := GetNodeObject(clientset, hostnameOverride)
	if err != nil {
		return "", fmt.Errorf("Failed to get pod CIDR allocated for the node due to: " + err.Error())
	}
	return node.Spec.PodCIDR, nil
}

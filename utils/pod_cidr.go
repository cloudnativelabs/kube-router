package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"reflect"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/plugins/ipam/host-local/backend/allocator"
	"k8s.io/client-go/kubernetes"
)

// GetPodCidrFromCniSpec gets pod CIDR allocated to the node from CNI spec file and returns it
func GetPodCidrFromCniSpec(cniConfFilePath string) (net.IPNet, error) {
	netconfig, err := libcni.ConfFromFile(cniConfFilePath)
	if err != nil {
		return net.IPNet{}, fmt.Errorf("Failed to load CNI conf file: %s", err.Error())
	}

	var ipamConfig *allocator.IPAMConfig
	ipamConfig, _, err = allocator.LoadIPAMConfig(netconfig.Bytes, "")
	if err != nil {
		return net.IPNet{}, fmt.Errorf("Failed to get IPAM details from the CNI conf file: %s", err.Error())
	}

	podCidr := net.IPNet(ipamConfig.Subnet)
	if reflect.DeepEqual(podCidr, net.IPNet{}) {
		return net.IPNet{}, errors.New("subnet missing from CNI IPAM")
	}

	return podCidr, nil
}

// InsertPodCidrInCniSpec inserts the pod CIDR allocated to the node by kubernetes controlller manager
// and stored it in the CNI specification
func InsertPodCidrInCniSpec(cniConfFilePath string, cidr string) error {
	file, err := ioutil.ReadFile(cniConfFilePath)
	if err != nil {
		return fmt.Errorf("Failed to load CNI conf file: %s", err.Error())
	}
	config := make(map[string]interface{})
	err = json.Unmarshal(file, &config)
	if err != nil {
		return fmt.Errorf("Failed to parse JSON from CNI conf file: %s", err.Error())
	}

	config["ipam"].(map[string]interface{})["subnet"] = cidr
	configJson, _ := json.Marshal(config)
	err = ioutil.WriteFile(cniConfFilePath, configJson, 0644)
	if err != nil {
		return fmt.Errorf("Failed to insert subnet cidr into CNI conf file: %s", err.Error())
	}
	return nil
}

// GetPodCidrFromNodeSpec reads the pod CIDR allocated to the node from API node object and returns it
func GetPodCidrFromNodeSpec(clientset *kubernetes.Clientset, hostnameOverride string) (string, error) {
	node, err := GetNodeObject(clientset, hostnameOverride)
	if err != nil {
		return "", fmt.Errorf("Failed to get pod CIDR allocated for the node due to: " + err.Error())
	}
	return node.Spec.PodCIDR, nil
}

package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"reflect"
	"strings"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/plugins/ipam/host-local/backend/allocator"
	"k8s.io/client-go/kubernetes"
)

// GetPodCidrFromCniSpec gets pod CIDR allocated to the node from CNI spec file and returns it
func GetPodCidrFromCniSpec(cniConfFilePath string) (net.IPNet, error) {
	var podCidr net.IPNet
	var err error
	var ipamConfig *allocator.IPAMConfig

	if strings.HasSuffix(cniConfFilePath, ".conflist") {
		var confList *libcni.NetworkConfigList
		confList, err = libcni.ConfListFromFile(cniConfFilePath)
		if err != nil {
			return net.IPNet{}, fmt.Errorf("Failed to load CNI config list file: %s", err.Error())
		}
		for _, conf := range confList.Plugins {
			if conf.Network.IPAM.Type != "" {
				ipamConfig, _, err = allocator.LoadIPAMConfig(conf.Bytes, "")
				if err != nil {
					return net.IPNet{}, fmt.Errorf("Failed to get IPAM details from the CNI conf file: %s", err.Error())
				}
				break
			}
		}
	} else {
		netconfig, err := libcni.ConfFromFile(cniConfFilePath)
		if err != nil {
			return net.IPNet{}, fmt.Errorf("Failed to load CNI conf file: %s", err.Error())
		}
		ipamConfig, _, err = allocator.LoadIPAMConfig(netconfig.Bytes, "")
		if err != nil {
			return net.IPNet{}, fmt.Errorf("Failed to get IPAM details from the CNI conf file: %s", err.Error())
		}
	}
	podCidr = net.IPNet(ipamConfig.Subnet)
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
	var config interface{}
	if strings.HasSuffix(cniConfFilePath, ".conflist") {
		err = json.Unmarshal(file, &config)
		if err != nil {
			return fmt.Errorf("Failed to parse JSON from CNI conf file: %s", err.Error())
		}
		updatedCidr := false
		configMap := config.(map[string]interface{})
		for key := range configMap {
			if key != "plugins" {
				continue
			}
			// .conflist file has array of plug-in config. Find the one with ipam key
			// and insert the CIDR for the node
			pluginConfigs := configMap["plugins"].([]interface{})
			for _, pluginConfig := range pluginConfigs {
				pluginConfigMap := pluginConfig.(map[string]interface{})
				if val, ok := pluginConfigMap["ipam"]; ok {
					valObj := val.(map[string]interface{})
					valObj["subnet"] = cidr
					updatedCidr = true
					break
				}
			}
		}

		if !updatedCidr {
			return fmt.Errorf("Failed to insert subnet cidr into CNI conf file: %s as CNI file is invalid.", cniConfFilePath)
		}

	} else {
		err = json.Unmarshal(file, &config)
		if err != nil {
			return fmt.Errorf("Failed to parse JSON from CNI conf file: %s", err.Error())
		}
		pluginConfig := config.(map[string]interface{})
		pluginConfig["ipam"].(map[string]interface{})["subnet"] = cidr
	}
	configJSON, _ := json.Marshal(config)
	err = ioutil.WriteFile(cniConfFilePath, configJSON, 0644)
	if err != nil {
		return fmt.Errorf("Failed to insert subnet cidr into CNI conf file: %s", err.Error())
	}
	return nil
}

// GetPodCidrFromNodeSpec reads the pod CIDR allocated to the node from API node object and returns it
func GetPodCidrFromNodeSpec(clientset kubernetes.Interface, hostnameOverride string) (string, error) {
	node, err := GetNodeObject(clientset, hostnameOverride)
	if err != nil {
		return "", fmt.Errorf("Failed to get pod CIDR allocated for the node due to: " + err.Error())
	}

	if node.Spec.PodCIDR == "" {
		return "", fmt.Errorf("node.Spec.PodCIDR not set for node: %v", node.Name)
	}

	return node.Spec.PodCIDR, nil
}

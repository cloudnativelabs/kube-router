package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/plugins/ipam/host-local/backend/allocator"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

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
	return net.IPNet(ipamConfig.Subnet), nil
}

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

func GetPodCidrFromNodeSpec(clientset *kubernetes.Clientset) (string, error) {
	nodeHostName, err := os.Hostname()
	if err != nil {
		panic(err.Error())
	}
	nodeFqdnHostName := GetFqdn()
	node, err := clientset.Core().Nodes().Get(nodeHostName, metav1.GetOptions{})
	if err != nil {
		node, err = clientset.Core().Nodes().Get(nodeFqdnHostName, metav1.GetOptions{})
		if err != nil {
			panic(err.Error())
		}
	}
	return node.Spec.PodCIDR, nil
}

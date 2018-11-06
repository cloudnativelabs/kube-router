package utils

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// GetNodeObject returns the node API object for the node
func GetNodeObject(clientset kubernetes.Interface, hostnameOverride string) (*apiv1.Node, error) {
	// assuming kube-router is running as pod, first check env NODE_NAME
	nodeName := os.Getenv("NODE_NAME")
	if nodeName != "" {
		node, err := clientset.Core().Nodes().Get(nodeName, metav1.GetOptions{})
		if err == nil {
			return node, nil
		}
	}

	// if env NODE_NAME is not set then check if node is register with hostname
	hostName, _ := os.Hostname()
	node, err := clientset.Core().Nodes().Get(hostName, metav1.GetOptions{})
	if err == nil {
		return node, nil
	}

	// if env NODE_NAME is not set and node is not registered with hostname, then use host name override
	if hostnameOverride != "" {
		node, err = clientset.Core().Nodes().Get(hostnameOverride, metav1.GetOptions{})
		if err == nil {
			return node, nil
		}
	}

	return nil, fmt.Errorf("Failed to identify the node by NODE_NAME, hostname or --hostname-override")
}

// GetNodeIP returns the most valid external facing IP address for a node.
// Order of preference:
// 1. NodeInternalIP
// 2. NodeExternalIP (Only set on cloud providers usually)
func GetNodeIP(node *apiv1.Node) (net.IP, error) {
	addresses := node.Status.Addresses
	addressMap := make(map[apiv1.NodeAddressType][]apiv1.NodeAddress)
	for i := range addresses {
		addressMap[addresses[i].Type] = append(addressMap[addresses[i].Type], addresses[i])
	}
	if addresses, ok := addressMap[apiv1.NodeInternalIP]; ok {
		return net.ParseIP(addresses[0].Address), nil
	}
	if addresses, ok := addressMap[apiv1.NodeExternalIP]; ok {
		return net.ParseIP(addresses[0].Address), nil
	}
	return nil, errors.New("host IP unknown")
}

//GetNodeWeight returns the node's weight based on the node's annotations
func GetNodeWeight(node *apiv1.Node, weightAnnotation string) (int, error) {
	var weight int
	var err error

	if weightString, found := node.ObjectMeta.Annotations[weightAnnotation]; found {
		if weight, err = strconv.Atoi(weightString); err == nil {
			return weight, nil
		}
	} else {
		err = fmt.Errorf("weight annotation '%s' not found on node %s", weightAnnotation, node.GetName())
	}

	return -1, err
}

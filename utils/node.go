package utils

import (
	"os"
	"fmt"

	"k8s.io/client-go/kubernetes"
	apiv1 "k8s.io/client-go/pkg/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func GetNodeObject(clientset *kubernetes.Clientset) (*apiv1.Node, error) {

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

	// if env NODE_NAME is not set then check if node is registerd by FQDN
	fqdnHostName := GetFqdn()
	node, err = clientset.Core().Nodes().Get(fqdnHostName, metav1.GetOptions{})
	if err == nil {
		return node, nil
	}

	return nil, fmt.Errorf("Failed to identify the node by NODE_NAME, hostname or FQDN name of the host")
}

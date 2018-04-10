package e2e

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	bgpclient "github.com/osrg/gobgp/client"

	v1core "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "E2E Suite")
}

func getNodePublicIP(node v1core.Node) (string, error) {
	for _, address := range node.Status.Addresses {
		if address.Type == v1core.NodeExternalIP {
			return address.Address, nil
		}
	}

	return "", errors.New("node did not have an external IP set")
}

func newBGPClient(nodeIP string) (*bgpclient.Client, error) {
	return bgpclient.New(nodeIP + ":50051")
}

func clientFromKubeConfig() (kubernetes.Interface, error) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		return nil, errors.New("KUBECONFIG is required")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return clientset, nil
}

func executeSSHCmd(command string, hostIP string, config *ssh.ClientConfig) (string, error) {
	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", hostIP), config)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Run(command)

	return stdoutBuf.String(), nil
}

func newSSHClientConfig() (*ssh.ClientConfig, error) {
	keyFile := os.Getenv("SSHKEY_FILE")
	if keyFile == "" {
		return nil, errors.New("SSHKEY_FILE is required")
	}

	key, err := sshKeyAuth(keyFile)
	if err != nil {
		return nil, err
	}

	return &ssh.ClientConfig{
		User: "core",
		Auth: []ssh.AuthMethod{
			key,
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}

func sshKeyAuth(file string) (ssh.AuthMethod, error) {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(key), nil
}

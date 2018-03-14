package utils

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"testing"
)

func Test_GetPodCidrFromCniSpec(t *testing.T) {
	testcases := []struct {
		name        string
		cniConfFile string
		podCidr     net.IPNet
		err         error
		filename    string
	}{
		{
			"CNI config file has subnet",
			`{"bridge":"kube-bridge","ipam":{"subnet":"172.17.0.0/24","type":"host-local"},"isDefaultGateway":true,"name":"kubernetes","type":"bridge"}`,
			net.IPNet{
				IP:   net.IPv4(172, 17, 0, 0),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			nil,
			"10-kuberouter.conf",
		},
		{
			"CNI config file missing subnet",
			`{"bridge":"kube-bridge","ipam":{"type":"host-local"},"isDefaultGateway":true,"name":"kubernetes","type":"bridge"}`,
			net.IPNet{},
			errors.New("subnet missing from CNI IPAM"),
			"10-kuberouter.conf",
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			file, err := createFile(testcase.cniConfFile, testcase.filename)
			if err != nil {
				t.Fatalf("Failed to create temporary CNI config file: %v", err)
			}
			defer os.Remove(file.Name())

			cidr, err := GetPodCidrFromCniSpec(file.Name())
			if !reflect.DeepEqual(err, testcase.err) {
				t.Logf("actual error: %v", err)
				t.Logf("expected error: %v", testcase.err)
				t.Error("did not get expected error")
			}

			if !reflect.DeepEqual(cidr, testcase.podCidr) {
				t.Logf("actual pod cidr: %v", cidr)
				t.Logf("expected pod cidr: %v", testcase.podCidr)
				t.Error("did not get expected pod cidr")
			}
		})
	}
}

func Test_InsertPodCidrInCniSpec(t *testing.T) {
	testcases := []struct {
		name        string
		podCidr     string
		existingCni string
		newCni      string
		err         error
		filename    string
	}{
		{
			"insert cidr to cni config",
			"172.17.0.0/24",
			`{"bridge":"kube-bridge","ipam":{"type":"host-local"},"isDefaultGateway":true,"name":"kubernetes","type":"bridge"}`,
			`{"bridge":"kube-bridge","ipam":{"subnet":"172.17.0.0/24","type":"host-local"},"isDefaultGateway":true,"name":"kubernetes","type":"bridge"}`,
			nil,
			"/tmp/10-kuberouter.conf",
		},
		{
			"insert cidr to cni config",
			"172.17.0.0/24",
			`{"cniVersion":"0.3.0","name":"mynet","plugins":[{"bridge":"kube-bridge","ipam":{"type":"host-local"},"isDefaultGateway":true,"name":"kubernetes","type":"bridge"},{"type":"portmap"}]}`,
			`{"cniVersion":"0.3.0","name":"mynet","plugins":[{"bridge":"kube-bridge","ipam":{"subnet":"172.17.0.0/24","type":"host-local"},"isDefaultGateway":true,"name":"kubernetes","type":"bridge"},{"type":"portmap"}]}`,
			nil,
			"/tmp/10-kuberouter.conflist",
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			cniConfigFile, err := createFile(testcase.existingCni, testcase.filename)

			if err != nil {
				t.Fatalf("failed to create temporary CNI config: %v", err)
			}
			defer os.Remove(cniConfigFile.Name())

			err = InsertPodCidrInCniSpec(cniConfigFile.Name(), testcase.podCidr)
			if !reflect.DeepEqual(err, testcase.err) {
				t.Logf("actual error: %v", err)
				t.Logf("expected error: %v", err)
				t.Error("did not get expected error")
			}

			newContent, err := readFile(cniConfigFile.Name())
			if err != nil {
				t.Fatalf("failed to read CNI config file: %v", err)
			}

			if newContent != testcase.newCni {
				t.Logf("actual CNI config: %v", newContent)
				t.Logf("expected CNI config: %v", testcase.newCni)
				t.Error("did not get expected CNI config content")
			}
		})
	}
}

func createFile(content, filename string) (*os.File, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot create file: %v", err)
	}

	if _, err = file.Write([]byte(content)); err != nil {
		return nil, fmt.Errorf("cannot write to file: %v", err)
	}

	fmt.Println("File is ", file.Name())
	return file, nil
}

func readFile(filename string) (string, error) {
	content, err := ioutil.ReadFile(filename)
	return string(content), err
}

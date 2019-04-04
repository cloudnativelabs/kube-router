package netpol_test

import (
	"bufio"
	"bytes"
	. "github.com/cloudnativelabs/kube-router/pkg/controllers/netpol"
	"strings"
	"testing"
)

func TestNFTablesSimpleIngress(t *testing.T) {
	pod1 := NewPodInfo("test-pod-1", "application-ns", "192.168.2.1")
	pod2 := NewPodInfo("test-pod-2", "application-ns", "192.168.2.2")
	inRule1 := NewIngressRule([]PodInfo{}, IpBlocks("192.168.4.2/24", "192.168.5.2/24"),
		Ports(NewTCPPort(80),
			NewTCPPort(8080)))

	eRule1 := NewEgressRule([]PodInfo{*pod2}, IpBlocks("192.168.4.2/24", "192.168.5.2/24"),
		Ports(NewTCPPort(443)))

	blocks := IpBlocks("192.168.8.0/24")
	blocks[0].Except = []string{"192.168.8.15/31", "192.168.8.50/31", "192.168.8.150/32"}
	eRule2 := NewEgressRule([]PodInfo{*pod1}, blocks, Ports(NewProtocolAndPort("UDP", nil)))

	np1 := NewNetworkPolicyInfo("test-policy1", "application-ns", "both", &[]IngressRule{inRule1}, &[]EgressRule{eRule1}, *pod1)
	np2 := NewNetworkPolicyInfo("test-policy2", "application-ns", "both", &[]IngressRule{}, &[]EgressRule{eRule2}, *pod2)

	iPods := make(map[string]PodInfo, 0)
	ePods := make(map[string]PodInfo, 0)
	iPods[pod1.IP] = *pod1
	ePods[pod2.IP] = *pod2

	nft, err := NewNFTablesHandler("192.168.7.0/23", false)
	if err != nil {
		t.Error(err.Error())
	}

	var buffer bytes.Buffer
	var writer = bufio.NewWriter(&buffer)
	if err := nft.Generate(writer, &NFTablesInfo{
		TableName:   "kube-router-test",
		EgressPods:  ePods,
		IngressPods: iPods,
		LocalIp4:    []string{"192.168.10.9"},
		LocalIp6:    []string{},
		Policies:    []NetworkPolicyInfo{*np1, *np2},
	}); err != nil {
		t.Error(err.Error())
	}
	writer.Flush()

	output := buffer.String()
	t.Log(output)

	if contains := strings.Contains(output, "ip daddr { 192.168.2.1, } ip saddr { 192.168.4.2/24,192.168.5.2/24 } tcp dport 80 accept"); !contains {
		t.Fail()
	}
	if contains := strings.Contains(output, "ip daddr { 192.168.2.1, } ip saddr { 192.168.4.2/24,192.168.5.2/24 } tcp dport 8080 accept"); !contains {
		t.Fail()
	}
	if contains := strings.Contains(output, "ip saddr { 192.168.2.1, } ip daddr { 192.168.2.2,192.168.4.2/24,192.168.5.2/24 } tcp dport 443 accept"); !contains {
		t.Fail()
	}
	if contains := strings.Contains(output, "ip saddr { 192.168.2.2, } ip daddr { 192.168.2.1,192.168.8.0/24 } ip daddr != { 192.168.8.15/31,192.168.8.50/31,192.168.8.150/32 } ip protocol udp accept"); !contains {
		t.Fail()
	}
	if contains := strings.Contains(output, "ip saddr { 192.168.10.9, } accept"); !contains {
		t.Fail()
	}
}

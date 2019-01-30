package netpol

import (
	"k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func NewNetworkPolicyInfo(name, namespace, policyTypes string, ingressRules *[]IngressRule, egressRules *[]EgressRule, targetPods ...PodInfo) *NetworkPolicyInfo {

	// make it easier to build test data by allowing one to pass in a slice of PodInfo instead of a map
	var targetPodsMap = make(map[string]PodInfo, 0)
	for _, info := range targetPods {
		targetPodsMap[info.IP] = info
	}

	ingRls := make([]IngressRule, 0)
	egrRls := make([]EgressRule, 0)
	if ingressRules != nil {
		ingRls = *ingressRules
	}
	if egressRules != nil {
		egrRls = *egressRules
	}

	return &NetworkPolicyInfo{
		Name:         name,
		Namespace:    namespace,
		policyType:   policyTypes,
		IngressRules: ingRls,
		EgressRules:  egrRls,
		TargetPods:   targetPodsMap,
	}
}

func NewIngressRule(srcPods []PodInfo, srcIpBlocks []*v1.IPBlock, ports []ProtocolAndPort) IngressRule {

	matchAllPorts := len(ports) < 1
	matchAllSource := len(srcPods) < 1 && len(srcIpBlocks) < 1

	return IngressRule{
		MatchAllPorts:  matchAllPorts,
		MatchAllSource: matchAllSource,
		SrcPods:        srcPods,
		SrcIPBlocks:    srcIpBlocks,
		Ports:          ports,
	}
}

func NewEgressRule(dstPods []PodInfo, dstIpBlocks []*v1.IPBlock, ports []ProtocolAndPort) EgressRule {

	matchAllPorts := len(ports) < 1
	matchAllSource := len(dstPods) < 1 && len(dstIpBlocks) < 1

	return EgressRule{
		MatchAllPorts:        matchAllPorts,
		MatchAllDestinations: matchAllSource,
		DstPods:              dstPods,
		DstIPBlocks:          dstIpBlocks,
		Ports:                ports,
	}
}

func PodInfos(podInfo ...PodInfo) []PodInfo {
	return podInfo
}

func Ports(ports ...ProtocolAndPort) []ProtocolAndPort {
	return ports
}

func IpBlocks(blocks ...string) [][]string {
	out := make([][]string, 0)
	for _, b := range blocks {
		out = append(out, []string{b})
	}
	return out
}

func NewPodInfo(name, namespace, ip string) *PodInfo {
	labels := make(map[string]string, 0)
	return &PodInfo{
		Name:      name,
		Namespace: namespace,
		IP:        ip,
		Labels:    labels,
	}
}

func NewTCPPort(port int) ProtocolAndPort {
	if port > 0 {
		intOrStr := intstr.FromInt(port)
		return NewProtocolAndPort("TCP", &intOrStr)
	} else {
		return NewProtocolAndPort("TCP", nil)
	}
}

func NewUDPPort(port int) ProtocolAndPort {
	if port > 0 {
		intOrStr := intstr.FromInt(port)
		return NewProtocolAndPort("UDP", &intOrStr)
	} else {
		return NewProtocolAndPort("UDP", nil)
	}
}

func NewProtocolAndPort(protocol string, port *intstr.IntOrString) ProtocolAndPort {
	strPort := ""

	if port != nil {
		strPort = port.String()
	}

	return ProtocolAndPort{Protocol: protocol, Port: strPort}
}

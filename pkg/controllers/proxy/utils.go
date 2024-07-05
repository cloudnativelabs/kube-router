package proxy

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/cri"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
)

const (
	interfaceWaitSleepTime = 100 * time.Millisecond
	sysFSVirtualNetPath    = "/sys/devices/virtual/net"
	sysFSHairpinRelPath    = "brport/hairpin_mode"
	hairpinEnable          = "1"
)

func attemptNamespaceResetAfterError(hostNSHandle netns.NsHandle) {
	err := netns.Set(hostNSHandle)
	if err != nil {
		klog.Errorf("failed to set hostNetworkNamespace while resetting namespace after a previous error due to %v",
			err)
	}
	activeNetworkNamespaceHandle, err := netns.Get()
	if err != nil {
		klog.Errorf("failed to confirm activeNetworkNamespace while resetting namespace after "+
			"a previous error due to %v", err)
		return
	}
	klog.V(2).Infof("Current network namespace after revert namespace to host network namespace: %s",
		activeNetworkNamespaceHandle.String())
	_ = activeNetworkNamespaceHandle.Close()
}

// generateUniqueFWMark generates a unique uint32 hash value using the IP address, port, and protocol. This can then
// be used in IPVS, ip rules, and iptables to mark and later identify packets. FWMarks along with ip, port, and protocol
// are then stored in a map on the NSC and can be used later for lookup and as a general translation layer. If after
// maxUniqueFWMarkInc tries, generateUniqueFWMark is not able to find a unique permutation to use, an error is returned.
func (nsc *NetworkServicesController) generateUniqueFWMark(ip, protocol, port string) (uint32, error) {
	// Generate a unit32 hash value using the IP address, port and protocol. This has been moved to an anonymous
	// function since calling this without guarantees of uniqueness is unsafe.
	generateFWMark := func(ip, protocol, port string, increment int) (uint32, error) {
		const maxFwMarkBitSize = 0x3FFF
		var err error
		h := fnv.New32a()
		if increment == 0 {
			_, err = h.Write([]byte(ip + "-" + protocol + "-" + port))
		} else {
			_, err = h.Write([]byte(ip + "-" + protocol + "-" + port + "-" + fmt.Sprintf("%d", increment)))
		}
		if err != nil {
			return 0, err
		}
		return h.Sum32() & maxFwMarkBitSize, err
	}

	const maxUniqueFWMarkInc = 16380
	increment := 0
	serviceKey := fmt.Sprintf("%s-%s-%s", ip, protocol, port)
	for {
		potentialFWMark, err := generateFWMark(ip, protocol, port, increment)
		if err != nil {
			return potentialFWMark, err
		}
		if foundServiceKey, ok := nsc.fwMarkMap[potentialFWMark]; ok {
			if foundServiceKey != serviceKey {
				increment++
				continue
			}
		}
		if increment >= maxUniqueFWMarkInc {
			return 0, fmt.Errorf("could not obtain a unique FWMark for %s:%s:%s after %d tries",
				protocol, ip, port, maxUniqueFWMarkInc)
		}
		nsc.fwMarkMap[potentialFWMark] = serviceKey
		return potentialFWMark, nil
	}
}

// lookupFWMarkByService finds the related FW mark from the internal fwMarkMap kept by the NetworkServiceController
// given the related ip, protocol, and port. If it isn't able to find a matching FW mark, then it returns an error.
func (nsc *NetworkServicesController) lookupFWMarkByService(ip, protocol, port string) uint32 {
	needle := fmt.Sprintf("%s-%s-%s", ip, protocol, port)
	for fwMark, serviceKey := range nsc.fwMarkMap {
		if needle == serviceKey {
			return fwMark
		}
	}
	return 0
}

// lookupServiceByFWMark Lookup service ip, protocol, port by given FW Mark value (reverse of lookupFWMarkByService)
func (nsc *NetworkServicesController) lookupServiceByFWMark(fwMark uint32) (string, string, int, error) {
	serviceKey, ok := nsc.fwMarkMap[fwMark]
	if !ok {
		return "", "", 0, fmt.Errorf("could not find service matching the given FW mark")
	}
	serviceKeySplit := strings.Split(serviceKey, "-")
	if len(serviceKeySplit) != 3 {
		return "", "", 0, fmt.Errorf("service key for found FW mark did not have 3 parts, this shouldn't be possible")
	}
	port, err := strconv.ParseInt(serviceKeySplit[2], 10, 32)
	if err != nil {
		return "", "", 0, fmt.Errorf("port number for service key for found FW mark was not a 32-bit int: %v", err)
	}
	return serviceKeySplit[0], serviceKeySplit[1], int(port), nil
}

// isValidKubeRouterServiceArtifact looks up a service by its clusterIP, externalIP, or loadBalancerIP. It returns
// truthy
func (nsc *NetworkServicesController) isValidKubeRouterServiceArtifact(address net.IP, nodePort int) (bool, error) {
	for _, svc := range nsc.serviceMap {
		for _, clIP := range svc.clusterIPs {
			if net.ParseIP(clIP).Equal(address) {
				return true, nil
			}
		}
		for _, exIP := range svc.externalIPs {
			if net.ParseIP(exIP).Equal(address) {
				return true, nil
			}
		}
		for _, lbIP := range svc.loadBalancerIPs {
			if net.ParseIP(lbIP).Equal(address) {
				return true, nil
			}
		}
		if nodePort != 0 && svc.nodePort == nodePort {
			if nsc.nodeportBindOnAllIP {
				addrMap, err := getAllLocalIPs()
				if err != nil {
					return false, fmt.Errorf("failed to get all local IPs: %v", err)
				}
				var addresses []net.IP
				if address.To4() != nil {
					addresses = addrMap[v1.IPv4Protocol]
				} else {
					addresses = addrMap[v1.IPv6Protocol]
				}
				for _, addr := range addresses {
					if addr.Equal(address) {
						return true, nil
					}
				}
			} else if address.Equal(nsc.primaryIP) {
				return true, nil
			}
		}
	}
	return false, fmt.Errorf("service not found for address %s", address.String())
}

// unsortedListsEquivalent compares two lists of endpointsInfo and considers them the same if they contains the same
// contents regardless of order. Returns true if both lists contain the same contents.
func unsortedListsEquivalent(a, b []endpointSliceInfo) bool {
	if len(a) != len(b) {
		return false
	}

	values := make(map[interface{}]int)
	for _, val := range a {
		values[val] = 1
	}
	for _, val := range b {
		values[val]++
	}

	for _, val := range values {
		if val == 1 {
			return false
		}
	}

	return true
}

// endpointsMapsEquivalent compares two maps of endpointsInfoMap to see if they have the same keys and values. Returns
// true if both maps contain the same keys and values.
func endpointsMapsEquivalent(a, b endpointSliceInfoMap) bool {
	if len(a) != len(b) {
		return false
	}

	for key, valA := range a {
		valB, ok := b[key]
		if !ok {
			return false
		}

		if !unsortedListsEquivalent(valA, valB) {
			return false
		}
	}

	return true
}

// convertSvcProtoToSysCallProto converts a string based protocol that we receive from Kubernetes via something like the
// serviceInfo object into the uint16 syscall version of the protocol that is capable of interfacing with aspects of the
// Linux sub-sysem like IPVS
func convertSvcProtoToSysCallProto(svcProtocol string) uint16 {
	switch svcProtocol {
	case tcpProtocol:
		return syscall.IPPROTO_TCP
	case udpProtocol:
		return syscall.IPPROTO_UDP
	default:
		return syscall.IPPROTO_NONE
	}
}

// convertSysCallProtoToSvcProto converts a syscall based protocol version to a string representation that Kubernetes
// and other parts of kube-router understand
func convertSysCallProtoToSvcProto(sysProtocol uint16) string {
	switch sysProtocol {
	case syscall.IPPROTO_TCP:
		return tcpProtocol
	case syscall.IPPROTO_UDP:
		return udpProtocol
	default:
		return noneProtocol
	}
}

// findContainerRuntimeReferences find the container runtime and container ID for a given endpoint IP do this by:
//   - Resolving the endpoint IP to a pod
//   - Ensure that the pod actually exists on the node in question
//   - Get the container ID of the primary container (since this function primarily allows us to enter the pod's
//     namespace, it doesn't really matter which container we choose here, if this function gets used for something
//     else in the future, this might have to be re-evaluated)
func (nsc *NetworkServicesController) findContainerRuntimeReferences(endpointIP string) (string, string, error) {
	podObj, err := nsc.getPodObjectForEndpointIP(endpointIP)
	if err != nil {
		return "", "", fmt.Errorf("failed to find endpoint with ip: %s. so skipping preparing endpoint for DSR",
			endpointIP)
	}

	// we are only concerned with endpoint pod running on current node
	if strings.Compare(podObj.Status.HostIP, nsc.primaryIP.String()) != 0 {
		return "", "", nil
	}

	containerURL := podObj.Status.ContainerStatuses[0].ContainerID
	runtime, containerID, err := cri.EndpointParser(containerURL)
	if err != nil {
		return "", "", fmt.Errorf("couldn't get containerID (container=%s, pod=%s). Skipping DSR endpoint set up",
			podObj.Spec.Containers[0].Name, podObj.Name)
	}

	if containerID == "" {
		return "", "", fmt.Errorf("failed to find container id for the endpoint with ip: %s so skipping preparing "+
			"endpoint for DSR", endpointIP)
	}

	return runtime, containerID, nil
}

// addDSRIPInsidePodNetNamespace takes a given external IP and endpoint IP for a DSR service and then uses the container
// runtime to add the external IP to a virtual interface inside the pod so that it can receive DSR traffic inside its
// network namespace.
func (nsc *NetworkServicesController) addDSRIPInsidePodNetNamespace(externalIP, endpointIP string) error {
	crRuntime, containerID, err := nsc.findContainerRuntimeReferences(endpointIP)
	if err != nil {
		return err
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNetworkNamespaceHandle, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get namespace due to %v", err)
	}
	defer utils.CloseCloserDisregardError(&hostNetworkNamespaceHandle)

	var pid int
	if crRuntime == "docker" {
		// WARN: This method is deprecated and will be removed once docker-shim is removed from kubelet.
		pid, err = nsc.ln.getContainerPidWithDocker(containerID)
		if err != nil {
			return fmt.Errorf("failed to prepare endpoint %s to do direct server return due to %v",
				endpointIP, err)
		}
	} else {
		// We expect CRI compliant runtimes here
		// ugly workaround, refactoring of pkg/Proxy is required
		pid, err = nsc.ln.getContainerPidWithCRI(nsc.dsr.runtimeEndpoint, containerID)
		if err != nil {
			return fmt.Errorf("failed to prepare endpoint %s to do DSR due to: %v", endpointIP, err)
		}
	}

	return nsc.ln.configureContainerForDSR(externalIP, endpointIP, containerID, pid, hostNetworkNamespaceHandle)
}

// getPrimaryAndCIDRsByFamily returns the best primary nodeIP and a slice of all of the relevant podCIDRs based upon a
// given IP family
func (nsc *NetworkServicesController) getPrimaryAndCIDRsByFamily(ipFamily v1.IPFamily) (string, []string) {
	var primaryIP string
	cidrMap := make(map[string]bool)
	//nolint:exhaustive // we don't need exhaustive searching for IP Families
	switch ipFamily {
	case v1.IPv4Protocol:
		// If we're not detected to be IPv4 capable break early
		if !nsc.isIPv4Capable {
			return "", nil
		}

		primaryIP = utils.FindBestIPv4NodeAddress(nsc.primaryIP, nsc.nodeIPv4Addrs).String()
		if len(nsc.podCidr) > 0 && netutils.IsIPv4CIDRString(nsc.podCidr) {
			cidrMap[nsc.podCidr] = true
		}
		if len(nsc.podIPv4CIDRs) > 0 {
			for _, cidr := range nsc.podIPv4CIDRs {
				if _, ok := cidrMap[cidr]; !ok {
					cidrMap[cidr] = true
				}
			}
		}
	case v1.IPv6Protocol:
		// If we're not detected to be IPv6 capable break early
		if !nsc.isIPv6Capable {
			return "", nil
		}

		primaryIP = utils.FindBestIPv6NodeAddress(nsc.primaryIP, nsc.nodeIPv6Addrs).String()
		if len(nsc.podCidr) > 0 && netutils.IsIPv6CIDRString(nsc.podCidr) {
			cidrMap[nsc.podCidr] = true
		}
		if len(nsc.podIPv6CIDRs) > 0 {
			for _, cidr := range nsc.podIPv6CIDRs {
				if _, ok := cidrMap[cidr]; !ok {
					cidrMap[cidr] = true
				}
			}
		}
	}

	cidrs := make([]string, len(cidrMap))
	idx := 0
	for cidr := range cidrMap {
		cidrs[idx] = cidr
		idx++
	}

	return primaryIP, cidrs
}

func (nsc *NetworkServicesController) getPodObjectForEndpointIP(endpointIP string) (*v1.Pod, error) {
	for _, obj := range nsc.podLister.List() {
		pod := obj.(*v1.Pod)
		for _, ip := range pod.Status.PodIPs {
			if strings.Compare(ip.IP, endpointIP) == 0 {
				return pod, nil
			}
		}
	}
	return nil, errors.New("Failed to find pod with ip " + endpointIP)
}

func (nsc *NetworkServicesController) getServiceForServiceInfo(svcIn *serviceInfo) (*v1.Service, error) {
	svc, err := nsc.client.CoreV1().Services(svcIn.namespace).Get(context.Background(), svcIn.name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return svc, err
}

func (nsc *NetworkServicesController) getPodListForService(svc *v1.Service) (*v1.PodList, error) {
	lbSet := labels.Set(svc.Spec.Selector)
	listOpts := metav1.ListOptions{LabelSelector: lbSet.AsSelector().String()}
	pods, err := nsc.client.CoreV1().Pods(svc.Namespace).List(context.Background(), listOpts)
	if err != nil {
		return nil, err
	}
	return pods, err
}

// GetAllClusterIPs returns all of the cluster IPs on a service separated into IPv4 and IPv6 lists
func getAllClusterIPs(svc *serviceInfo) map[v1.IPFamily][]net.IP {
	// We use maps here so that we can de-duplicate repeat IP addresses
	v4Map := make(map[string]bool)
	v6Map := make(map[string]bool)

	if svc.clusterIP != nil {
		if svc.clusterIP.To4() != nil {
			v4Map[svc.clusterIP.String()] = true
		} else {
			v6Map[svc.clusterIP.String()] = true
		}
	}

	for _, clIP := range svc.clusterIPs {
		ip := net.ParseIP(clIP)
		if ip == nil {
			continue
		}

		if ip.To4() != nil {
			v4Map[ip.String()] = true
		} else {
			v6Map[ip.String()] = true
		}
	}

	return convertIPMapsToFamilyMap(v4Map, v6Map)
}

// getAllClusterIPs returns all of the cluster IPs on a service separated into IPv4 and IPv6 lists
func getAllExternalIPs(svc *serviceInfo, includeLBIPs bool) map[v1.IPFamily][]net.IP {
	// We use maps here so that we can de-duplicate repeat IP addresses
	v4Map := make(map[string]bool)
	v6Map := make(map[string]bool)

	for _, exIP := range svc.externalIPs {
		ip := net.ParseIP(exIP)
		if ip == nil {
			continue
		}

		if ip.To4() != nil {
			v4Map[ip.String()] = true
		} else {
			v6Map[ip.String()] = true
		}
	}

	if !includeLBIPs {
		return convertIPMapsToFamilyMap(v4Map, v6Map)
	}

	for _, lbIP := range svc.loadBalancerIPs {
		ip := net.ParseIP(lbIP)
		if ip == nil {
			continue
		}

		if ip.To4() != nil {
			v4Map[ip.String()] = true
		} else {
			v6Map[ip.String()] = true
		}
	}

	return convertIPMapsToFamilyMap(v4Map, v6Map)
}

// convertIPMapsToFamilyMap converts family specific maps of string IPs to a single map that is keyed by IPFamily and
// has parsed net.IPs
func convertIPMapsToFamilyMap(v4Map map[string]bool, v6Map map[string]bool) map[v1.IPFamily][]net.IP {
	allIPs := make(map[v1.IPFamily][]net.IP)

	allIPs[v1.IPv4Protocol] = make([]net.IP, len(v4Map))
	allIPs[v1.IPv6Protocol] = make([]net.IP, len(v6Map))

	idx := 0
	for ip := range v4Map {
		allIPs[v1.IPv4Protocol][idx] = net.ParseIP(ip)
		idx++
	}

	idx = 0
	for ip := range v6Map {
		allIPs[v1.IPv6Protocol][idx] = net.ParseIP(ip)
		idx++
	}

	return allIPs
}

// hairpinRuleFrom create hairpin rules for a given set of parameters
func hairpinRuleFrom(serviceIPs []net.IP, endpointIP string, endpointFamily v1.IPFamily, servicePort int,
	ruleMap map[string][]string) {
	var vipSubnet string

	//nolint:exhaustive // we don't need exhaustive searching for IP Families
	switch endpointFamily {
	case v1.IPv4Protocol:
		vipSubnet = "/32"
	case v1.IPv6Protocol:
		vipSubnet = "/128"
	}

	for _, svcIP := range serviceIPs {
		ruleArgs := []string{"-s", endpointIP + vipSubnet, "-d", endpointIP + vipSubnet,
			"-m", "ipvs", "--vaddr", svcIP.String(), "--vport", strconv.Itoa(servicePort),
			"-j", "SNAT", "--to-source", svcIP.String()}

		// Trying to ensure this matches iptables.List()
		ruleString := "-A " + ipvsHairpinChainName + " -s " + endpointIP + vipSubnet + " -d " +
			endpointIP + vipSubnet + " -m ipvs" + " --vaddr " + svcIP.String() + " --vport " +
			strconv.Itoa(servicePort) + " -j SNAT" + " --to-source " + svcIP.String()

		ruleMap[ruleString] = ruleArgs
	}
}

// ensureHairpinChain make sure that the hairpin chain in the nat table exists and that it has a jump rule from the
// POSTROUTING chain
func ensureHairpinChain(iptablesCmdHandler utils.IPTablesHandler) error {
	hasHairpinChain := false
	chains, err := iptablesCmdHandler.ListChains("nat")
	if err != nil {
		return fmt.Errorf("failed to list iptables chains: %v", err)
	}
	for _, chain := range chains {
		if chain == ipvsHairpinChainName {
			hasHairpinChain = true
		}
	}

	// Create a chain for hairpin rules, if needed
	if !hasHairpinChain {
		err = iptablesCmdHandler.NewChain("nat", ipvsHairpinChainName)
		if err != nil {
			return fmt.Errorf("failed to create iptables chain \"%s\": %v", ipvsHairpinChainName, err)
		}
	}

	// Create a jump that points to our hairpin chain
	jumpArgs := []string{"-m", "ipvs", "--vdir", "ORIGINAL", "-j", ipvsHairpinChainName}
	err = iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", jumpArgs...)
	if err != nil {
		return fmt.Errorf("failed to add hairpin iptables jump rule: %v", err)
	}

	return nil
}

// getAllLocalIPs returns all IP addresses found on any network address in the system, excluding dummy and docker
// interfaces in a map that distinguishes between IPv4 and IPv6 addresses by v1.IPFamily
func getAllLocalIPs() (map[v1.IPFamily][]net.IP, error) {
	// We use maps here so that we can de-duplicate repeat IP addresses
	v4Map := make(map[string]bool)
	v6Map := make(map[string]bool)
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("could not load list of net interfaces: %v", err)
	}

	for _, link := range links {
		// do not include IPs for any interface that calls itself "dummy", "kube", or "docker"
		if strings.Contains(link.Attrs().Name, "dummy") ||
			strings.Contains(link.Attrs().Name, "kube") ||
			strings.Contains(link.Attrs().Name, "docker") {

			continue
		}

		linkAddrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return nil, fmt.Errorf("failed to get IPs for interface: %v", err)
		}

		for _, addr := range linkAddrs {
			if addr.IP.To4() != nil {
				v4Map[addr.IP.String()] = true
			} else {
				v6Map[addr.IP.String()] = true
			}
		}
	}

	return convertIPMapsToFamilyMap(v4Map, v6Map), nil
}

// getIPSetName formulates an IP Family specific ipset name based upon the prefix and IPFamily passed
func getIPSetName(nameBase string, family v1.IPFamily) string {
	var sb strings.Builder

	if family == v1.IPv6Protocol {
		sb.WriteString("inet6:")
	}
	sb.WriteString(nameBase)

	return sb.String()
}

// getIPVSFirewallInputChainRule creates IPVS firwall input chain rule based upon the family that is passed. This is
// used by the NSC to ensure that traffic destined for IPVS services on the INPUT table will be directed to the IPVS
// firewall chain
func getIPVSFirewallInputChainRule(family v1.IPFamily) []string {
	// The iptables rule for use in {setup,cleanup}IpvsFirewall.
	return []string{
		"-m", "comment", "--comment", "handle traffic to IPVS service IPs in custom chain",
		"-m", "set", "--match-set", getIPSetName(serviceIPsIPSetName, family), "dst",
		"-j", ipvsFirewallChainName}
}

// runIPCommandsWithArgs extend the exec.Command interface to allow passing an additional array of arguments to ip
func runIPCommandsWithArgs(ipArgs []string, additionalArgs ...string) *exec.Cmd {
	var allArgs []string
	allArgs = append(allArgs, ipArgs...)
	allArgs = append(allArgs, additionalArgs...)
	return exec.Command("ip", allArgs...)
}

// getLabelFromMap checks the list of passed labels for the service.kubernetes.io/service-proxy-name
// label and if it exists, returns it otherwise returns an error
func getLabelFromMap(label string, labels map[string]string) (string, error) {
	for lbl, val := range labels {
		if lbl == label {
			return val, nil
		}
	}

	return "", fmt.Errorf("label doesn't exist in map")
}

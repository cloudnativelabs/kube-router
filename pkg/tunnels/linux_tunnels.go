// Package tunnels provides functionality for setting up and managing overlay tunnels in Linux.
// It includes support for both IPIP and FOU (Foo over Ethernet) encapsulation types.
//
// As much functionality as possible is done via the netlink library, however, FOU tunnels require using the iproute2
// user space tooling since they are not currently supported by the netlink library.
package tunnels

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	"github.com/cloudnativelabs/kube-router/v2/pkg/routes"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

const (
	EncapTypeFOU  = EncapType("fou")
	EncapTypeIPIP = EncapType("ipip")

	// FOU modes used for the iproute2 tooling
	fouIPv4LinkMode = "ipip"
	fouIPv6LinkMode = "ip6tnl"

	// IPIP modes used for the iproute2 tooling
	ipipIPv4Mode = "ipip"
	ipipIPv6Mode = "ip6ip6"

	// The maximum and minimum port numbers for encap ports
	maxPort = uint16(65535)
	minPort = uint16(1024)

	// Unix tunnel encap types, unfortunately, these are not understood by the netlink library, so we need to use
	// our own enums which as far as I can tell come from here:
	//nolint:lll // URL is long
	// https://github.com/iproute2/iproute2/blob/e6a170a9d4e75d206631da77e469813279c12134/include/uapi/linux/if_tunnel.h#L84-L89
	UnixTunnelEncapTypeNone uint16 = 0
	UnixTunnelEncapTypeFOU  uint16 = 1
	UnixTunnelEncapTypeGUE  uint16 = 2
	UnixTunnelEncapTypeMPLS uint16 = 3
)

var (
	validEncapTypes = []EncapType{EncapTypeFOU, EncapTypeIPIP}
)

// tunnelConfig holds configuration for IP family-specific settings
type tunnelConfig struct {
	nextHopSubnet   *net.IPNet
	bestIPForFamily net.IP
	ipipMode        string
	fouLinkType     string
	isIPv6          bool
	ipBase          []string
	encapPortStr    string
}

// EncapType represents the type of encapsulation used for an overlay tunnel in kube-router.
type EncapType string

// ParseEncapType parses the given string and returns an Encap type if valid.
// It returns an error if the encapsulation type is invalid.
//
// Parameters:
//   - s: A string representing the encapsulation type.
//
// Returns:
//   - Encap: The parsed encapsulation type.
//   - bool: A boolean indicating whether the encapsulation type is valid.
func ParseEncapType(encapType string) (EncapType, bool) {
	encap := EncapType(encapType)
	if !slices.Contains(validEncapTypes, encap) {
		return "", false
	}
	return encap, true
}

type EncapPort uint16

func (e EncapPort) checkWithinRange() error {
	if uint16(e) >= minPort {
		return nil
	}
	return fmt.Errorf("specified encap port is out of range of valid ports: %d, valid range is from %d to %d",
		e, minPort, maxPort)
}

func ParseEncapPort(encapPort uint16) (EncapPort, error) {
	port := EncapPort(encapPort)
	if err := port.checkWithinRange(); err != nil {
		return 0, err
	}
	return port, nil
}

type Tunneler interface {
	SetupOverlayTunnel(tunnelName string, nextHop net.IP, nextHopSubnet *net.IPNet) (netlink.Link, error)
	EncapType() EncapType
	EncapPort() EncapPort
}

type OverlayTunnel struct {
	krNode    utils.NodeIPAware
	encapPort EncapPort
	encapType EncapType
}

func NewOverlayTunnel(krNode utils.NodeIPAware, encapType EncapType, encapPort EncapPort) *OverlayTunnel {
	return &OverlayTunnel{
		krNode:    krNode,
		encapPort: encapPort,
		encapType: encapType,
	}
}

func (o *OverlayTunnel) EncapType() EncapType {
	return o.encapType
}

func (o *OverlayTunnel) EncapPort() EncapPort {
	return o.encapPort
}

// setupOverlayTunnel attempts to create a tunnel link and corresponding routes for IPIP based overlay networks
func (o *OverlayTunnel) SetupOverlayTunnel(tunnelName string, nextHop net.IP,
	nextHopSubnet *net.IPNet) (netlink.Link, error) {
	link, err := netlink.LinkByName(tunnelName)
	if err != nil {
		klog.Warningf("failed to get tunnel link by name %s: %v, will attempt to create it", tunnelName, err)
		link = nil
	}

	// Determine IP family and configuration
	config, err := o.createTunnelConfig(nextHop, nextHopSubnet)
	if err != nil {
		return nil, err
	}

	// Check if tunnel needs recreation due to encap type mismatch
	link, err = o.applyTunnelConfig(link, tunnelName, nextHop, config)
	if err != nil {
		return nil, err
	}

	// Add route for the tunnel
	if err := o.addTunnelRoute(link, nextHop, config.isIPv6); err != nil {
		return nil, err
	}

	return link, nil
}

// createTunnelConfig determines the IP family and returns appropriate configuration
func (o *OverlayTunnel) createTunnelConfig(nextHop net.IP, nextHopSubnet *net.IPNet) (*tunnelConfig, error) {
	config := &tunnelConfig{
		ipBase:        make([]string, 0),
		encapPortStr:  strconv.FormatInt(int64(o.encapPort), 10),
		nextHopSubnet: nextHopSubnet,
	}

	if nextHop.To4() != nil {
		config.bestIPForFamily = o.krNode.FindBestIPv4NodeAddress()
		config.ipipMode = ipipIPv4Mode
		config.fouLinkType = fouIPv4LinkMode
		config.isIPv6 = false
	} else {
		config.ipBase = append(config.ipBase, "-6")
		config.bestIPForFamily = o.krNode.FindBestIPv6NodeAddress()
		config.ipipMode = ipipIPv6Mode
		config.fouLinkType = fouIPv6LinkMode
		config.isIPv6 = true
	}

	if config.bestIPForFamily == nil {
		return nil, fmt.Errorf("not able to find an appropriate configured IP address on node for destination "+
			"IP family: %s", nextHop.String())
	}

	return config, nil
}

// applyTunnelConfig ensures that the existing tunnel matches the desired configuration and cleans up any old tunnels
// that do not match the config
func (o *OverlayTunnel) applyTunnelConfig(link netlink.Link, tunnelName string, nextHop net.IP,
	config *tunnelConfig) (netlink.Link, error) {

	var recreate bool
	switch o.encapType {
	case EncapTypeIPIP:
		recreate = o.checkIPIPTunnelRecreation(tunnelName, config)
	case EncapTypeFOU:
		recreate = o.checkFOUTunnelRecreation(tunnelName, config)
	default:
		return nil, fmt.Errorf("unknown tunnel encapsulation was passed: %s, unable to continue with overlay "+
			"setup", o.encapType)
	}

	// If the link doesn't exist here, then it means that it likely doesn't exist, or we encountered a random error when
	// we originally tried to get it. In either case, we need to create a new tunnel.
	if link == nil || recreate {
		return o.createTunnel(tunnelName, nextHop, config)
	}

	return link, nil
}

// checkIPIPTunnelRecreation checks if IPIP tunnel needs recreation and cleans up any old tunnels
func (o *OverlayTunnel) checkIPIPTunnelRecreation(tunnelName string, config *tunnelConfig) bool {
	fouEnabled, err := linkFOUEnabled(tunnelName)
	if err != nil || fouEnabled {
		if err != nil {
			klog.Infof("failed to check if fou is enabled on the link %s: %v, going to try to clean up and "+
				"recreate the tunnel anyway", tunnelName, err)
		} else {
			klog.Infof("Was configured to use ipip tunnels, but found existing fou tunnels in place, " +
				"cleaning up")
		}

		// Clean up existing FOU tunnel
		CleanupTunnel(config.nextHopSubnet, tunnelName)

		// Clean up old FOU port if transitioning from FOU to IPIP
		if fouPortAndProtoExist(o.encapPort, config.isIPv6) {
			o.cleanupFOUPort(config)
		}

		return true
	}
	return false
}

// checkFOUTunnelRecreation checks if FOU tunnel needs recreation and cleans up any old tunnels
func (o *OverlayTunnel) checkFOUTunnelRecreation(tunnelName string, config *tunnelConfig) bool {
	fouEnabled, err := linkFOUEnabled(tunnelName)
	if err != nil || !fouEnabled {
		if err != nil {
			klog.Errorf("failed to check if fou is enabled on the link %s: %v, going to try to clean up and "+
				"recreate the tunnel anyway", tunnelName, err)
		} else {
			klog.Infof("Was configured to use fou tunnels, but found existing ipip tunnels in place, " +
				"cleaning up")
		}

		// Clean up existing IPIP tunnel
		CleanupTunnel(config.nextHopSubnet, tunnelName)
		return true
	}
	return false
}

// cleanupFOUPort removes the FOU port configuration
func (o *OverlayTunnel) cleanupFOUPort(config *tunnelConfig) {
	fouArgs := config.ipBase
	fouArgs = append(fouArgs, "fou", "del", "port", config.encapPortStr)
	out, err := exec.Command("ip", fouArgs...).CombinedOutput()
	if err != nil {
		klog.Warningf("failed to clean up previous FoU tunnel port (this is only a warning because it "+
			"won't stop kube-router from working for now, but still shouldn't have happened) - error: "+
			"%v, output %s", err, out)
	}
}

// createTunnel creates a new tunnel based on the encapsulation type
func (o *OverlayTunnel) createTunnel(tunnelName string, nextHop net.IP, config *tunnelConfig) (netlink.Link, error) {
	klog.Infof("Creating tunnel %s with encap %s for destination %s",
		tunnelName, o.encapType, nextHop.String())

	switch o.encapType {
	case EncapTypeIPIP:
		return o.createIPIPTunnel(tunnelName, nextHop, config)
	case EncapTypeFOU:
		return o.createFOUTunnel(tunnelName, nextHop, config)
	default:
		return nil, fmt.Errorf("unknown tunnel encapsulation was passed: %s, unable to continue with overlay "+
			"setup", o.encapType)
	}
}

// createIPIPTunnel creates an IPIP tunnel using netlink
func (o *OverlayTunnel) createIPIPTunnel(tunnelName string, nextHop net.IP,
	config *tunnelConfig) (netlink.Link, error) {
	var tunnelLink netlink.Link
	if config.isIPv6 {
		tunnelLink = &netlink.Ip6tnl{
			LinkAttrs: netlink.LinkAttrs{Name: tunnelName},
			Local:     config.bestIPForFamily,
			Remote:    nextHop,
		}
	} else {
		tunnelLink = &netlink.Iptun{
			LinkAttrs: netlink.LinkAttrs{Name: tunnelName},
			Local:     config.bestIPForFamily,
			Remote:    nextHop,
		}
	}

	if err := netlink.LinkAdd(tunnelLink); err != nil {
		return nil, fmt.Errorf("route not injected for the route advertised by the node %s "+
			"Failed to create tunnel interface %s. error: %v", nextHop, tunnelName, err)
	}

	return o.bringTunnelUp(tunnelName)
}

// createFOUTunnel creates a FOU tunnel
func (o *OverlayTunnel) createFOUTunnel(tunnelName string, nextHop net.IP, config *tunnelConfig) (netlink.Link, error) {
	// Ensure FOU port exists
	if err := o.ensureFOUPort(config); err != nil {
		return nil, err
	}

	// Create FOU tunnel using iproute2
	if err := o.createFOUTunnelWithIPRoute2(tunnelName, nextHop, config); err != nil {
		return nil, err
	}

	return o.bringTunnelUp(tunnelName)
}

// ensureFOUPort ensures the FOU port is configured
func (o *OverlayTunnel) ensureFOUPort(config *tunnelConfig) error {
	if fouPortAndProtoExist(o.encapPort, config.isIPv6) {
		return nil
	}

	var family int
	if config.isIPv6 {
		family = netlink.FAMILY_V6
	} else {
		family = netlink.FAMILY_V4
	}

	fouPort := &netlink.Fou{
		Family:    family,
		Port:      int(o.encapPort),
		EncapType: netlink.FOU_ENCAP_GUE,
	}

	if err := netlink.FouAdd(*fouPort); err != nil {
		return fmt.Errorf("failed to set FoU tunnel port - error: %v", err)
	}

	return nil
}

// createFOUTunnelWithIPRoute2 creates FOU tunnel using iproute2 command. While it would be nice to be able to do this
// via netlink, the netlink library does not currently support creating secondary encap tunnels (IPIP over GUE). So for
// now we have to use the iproute2 user-space tooling.
func (o *OverlayTunnel) createFOUTunnelWithIPRoute2(tunnelName string, nextHop net.IP, config *tunnelConfig) error {
	cmdArgs := config.ipBase
	cmdArgs = append(cmdArgs, "link", "add", "name", tunnelName, "type", config.fouLinkType, "remote", nextHop.String(),
		"local", config.bestIPForFamily.String(), "ttl", "225", "encap", "gue", "encap-sport", "auto", "encap-dport",
		config.encapPortStr, "mode", config.ipipMode)

	klog.V(2).Infof("Executing the following command to create tunnel: ip %s", cmdArgs)
	out, err := exec.Command("ip", cmdArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("route not injected for the route advertised by the node %s "+
			"Failed to create tunnel interface %s. error: %s, output: %s",
			nextHop, tunnelName, err, string(out))
	}

	return nil
}

// bringTunnelUp brings the tunnel interface up
func (o *OverlayTunnel) bringTunnelUp(tunnelName string) (netlink.Link, error) {
	link, err := netlink.LinkByName(tunnelName)
	if err != nil {
		return nil, fmt.Errorf("route not injected for the route advertised by the node %s "+
			"Failed to get tunnel interface by name error: %s", tunnelName, err)
	}

	if err = netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("failed to bring tunnel interface %s up due to: %v", tunnelName, err)
	}

	return link, nil
}

// addTunnelRoute adds a route for the tunnel in the custom table. This is necessary to ensure that the tunnel is used
// for all traffic destined for the tunnel's destination.
func (o *OverlayTunnel) addTunnelRoute(link netlink.Link, nextHop net.IP, isIPv6 bool) error {
	routeFamily := netlink.FAMILY_V4
	if isIPv6 {
		routeFamily = netlink.FAMILY_V6
	}

	route := &netlink.Route{
		Family:    routeFamily,
		LinkIndex: link.Attrs().Index,
		Table:     routes.CustomTableID,
		Dst:       utils.GetSingleIPNet(nextHop),
	}

	routeList, err := netlink.RouteListFiltered(routeFamily, route,
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
	if err != nil {
		return fmt.Errorf("failed to list routes in custom table: %v", err)
	}

	if len(routeList) < 1 {
		if err = netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("failed to add route in custom route table, err: %v", err)
		}
	} else {
		klog.V(2).Infof("Route for %s already exists in custom table", nextHop.String())
	}

	return nil
}

// cleanupTunnel removes any traces of tunnels / routes that were setup by nrc.setupOverlayTunnel() and are no longer
// needed. All errors are logged only, as we want to attempt to perform all cleanup actions regardless of their success
func CleanupTunnel(destinationSubnet *net.IPNet, tunnelName string) {
	klog.V(1).Infof("Cleaning up old routes for %s if there are any", destinationSubnet.String())
	if err := routes.DeleteByDestination(destinationSubnet); err != nil {
		klog.Errorf("Failed to cleanup routes: %v", err)
	}

	klog.V(1).Infof("Cleaning up any lingering tunnel interfaces named: %s", tunnelName)
	if link, err := netlink.LinkByName(tunnelName); err == nil {
		if err = netlink.LinkDel(link); err != nil {
			klog.Errorf("failed to delete tunnel link for the node due to %v", err)
		}
	}
}

// GenerateTunnelName will generate a name for a tunnel interface given a node IP
// Since linux restricts interface names to 15 characters, we take the sha-256 of the node IP after removing
// non-entropic characters like '.' and ':', and then use the first 12 bytes of it. This allows us to cater to both
// long IPv4 addresses and much longer IPv6 addresses.
//
// TODO: In the future, we should consider using the hexadecimal byte representation of IPv4 addresses and using a the
// SHA256 of the hash. Additionally, we should not remove non-entropic characters as it can cause hash collisions as
// "21.3.0.4" would has the same as "2.13.0.4" without "."'s.
func GenerateTunnelName(nodeIP string) string {
	// remove dots from an IPv4 address
	strippedIP := strings.ReplaceAll(nodeIP, ".", "")
	// remove colons from an IPv6 address
	strippedIP = strings.ReplaceAll(strippedIP, ":", "")

	h := sha256.New()
	h.Write([]byte(strippedIP))
	sum := h.Sum(nil)

	return "tun-" + fmt.Sprintf("%x", sum)[0:11]
}

// fouPortAndProtoExist checks to see if the given FoU port is already configured on the system via iproute2
// tooling for the given protocol
func fouPortAndProtoExist(port EncapPort, isIPv6 bool) bool {
	strPort := strconv.FormatInt(int64(port), 10)
	klog.V(2).Infof("Checking FOU Port and Proto... %s - %t", strPort, isIPv6)

	nFamily := netlink.FAMILY_V4
	if isIPv6 {
		nFamily = netlink.FAMILY_V6
	}

	fList, err := netlink.FouList(nFamily)
	if err != nil {
		klog.Warningf("failed to list fou ports: %v", err)
		return false
	}

	for _, fou := range fList {
		klog.V(2).Infof("Found fou port: %v", fou)
		if fou.Port == int(port) && fou.Family == nFamily {
			return true
		}
	}

	return false
}

// linkFOUEnabled checks to see whether the given link has FoU (Foo over Ethernet) enabled on it, specifically since
// kube-router only works with GUE (Generic UDP Encapsulation) we look for that and not just FoU in general. If the
// linkName is enabled with FoU GUE then we return true, otherwise false
func linkFOUEnabled(linkName string) (bool, error) {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return false, fmt.Errorf("failed to get link by name: %v", err)
	}

	switch link := link.(type) {
	case *netlink.Iptun:
		klog.V(2).Infof("Link %s is an IPTun with encap type: %d and encap dport: %d",
			linkName, link.EncapType, link.EncapDport)
		if link.EncapType == UnixTunnelEncapTypeGUE {
			return true, nil
		}
	case *netlink.Ip6tnl:
		klog.V(2).Infof("Link %s is an IP6Tun with encap type: %d and encap dport: %d",
			linkName, link.EncapType, link.EncapDport)
		if link.EncapType == UnixTunnelEncapTypeGUE {
			return true, nil
		}
	default:
		return false, fmt.Errorf("link %s is not an IPTun or IP6Tun, this is not expected", linkName)
	}

	return false, nil
}

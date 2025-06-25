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
	// https://github.com/iproute2/iproute2/blob/e6a170a9d4e75d206631da77e469813279c12134/include/uapi/linux/if_tunnel.h#L84-L89
	UnixTunnelEncapTypeNone uint16 = 0
	UnixTunnelEncapTypeFOU  uint16 = 1
	UnixTunnelEncapTypeGUE  uint16 = 2
	UnixTunnelEncapTypeMPLS uint16 = 3
)

var (
	validEncapTypes = []EncapType{EncapTypeFOU, EncapTypeIPIP}
)

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

	var bestIPForFamily net.IP
	var ipipMode, fouLinkType string
	isIPv6 := false
	ipBase := make([]string, 0)
	strFormattedEncapPort := strconv.FormatInt(int64(o.encapPort), 10)

	if nextHop.To4() != nil {
		bestIPForFamily = o.krNode.FindBestIPv4NodeAddress()
		ipipMode = ipipIPv4Mode
		fouLinkType = fouIPv4LinkMode
	} else {
		// Need to activate the ip command in IPv6 mode
		ipBase = append(ipBase, "-6")
		bestIPForFamily = o.krNode.FindBestIPv6NodeAddress()
		ipipMode = ipipIPv6Mode
		fouLinkType = fouIPv6LinkMode
		isIPv6 = true
	}
	if nil == bestIPForFamily {
		return nil, fmt.Errorf("not able to find an appropriate configured IP address on node for destination "+
			"IP family: %s", nextHop.String())
	}

	// This indicated that the tunnel already exists, so it's possible that there might be nothing more needed. However,
	// it is also possible that the user changed the encap type, so we need to make sure that the encap type matches
	// and if it doesn't, create it
	recreate := false
	if err == nil {
		klog.V(1).Infof("Tunnel interface: %s with encap type %s for the node %s already exists.",
			tunnelName, link.Attrs().EncapType, nextHop.String())

		switch o.encapType {
		case EncapTypeIPIP:
			if fouEnabled, err := linkFOUEnabled(tunnelName); err != nil || fouEnabled {
				if err != nil {
					klog.Errorf("failed to check if fou is enabled on the link %s: %v, going to try to clean up and "+
						"recreate the tunnel", tunnelName, err)
				} else {
					klog.Infof("Was configured to use ipip tunnels, but found existing fou tunnels in place, " +
						"cleaning up")
				}
				recreate = true

				// Even though we are setup for IPIP tunels we have existing tunnels that are FoU tunnels, remove them
				// so that we can recreate them as IPIP
				CleanupTunnel(nextHopSubnet, tunnelName)

				// If we are transitioning from FoU to IPIP we also need to clean up the old FoU port if it exists
				if fouPortAndProtoExist(o.encapPort, isIPv6) {
					fouArgs := ipBase
					fouArgs = append(fouArgs, "fou", "del", "port", strFormattedEncapPort)
					out, err := exec.Command("ip", fouArgs...).CombinedOutput()
					if err != nil {
						klog.Warningf("failed to clean up previous FoU tunnel port (this is only a warning because it "+
							"won't stop kube-router from working for now, but still shouldn't have happened) - error: "+
							"%v, output %s", err, out)
					}
				}
			}
		case EncapTypeFOU:
			if fouEnabled, err := linkFOUEnabled(tunnelName); err != nil || !fouEnabled {
				if err != nil {
					klog.Errorf("failed to check if fou is enabled on the link %s: %v, going to try to clean up and "+
						"recreate the tunnel", tunnelName, err)
				} else {
					klog.Infof("Was configured to use fou tunnels, but found existing ipip tunnels in place, " +
						"cleaning up")
				}
				recreate = true
				// Even though we are setup for FoU tunels we have existing tunnels that are IPIP tunnels, remove them
				// so that we can recreate them as IPIP
				CleanupTunnel(nextHopSubnet, tunnelName)
			}
		default:
			return nil, fmt.Errorf("unknown tunnel encapsulation was passed: %s, unable to continue with overlay "+
				"setup", o.encapType)
		}
	}

	// an error here indicates that the tunnel didn't exist, so we need to create it, if it already exists there's
	// nothing to do here
	if err != nil || recreate {
		klog.Infof("Creating tunnel %s with encap %s for destination %s",
			tunnelName, o.encapType, nextHop.String())

		switch o.encapType {
		case EncapTypeIPIP:
			// Create plain IPIP tunnel using netlink
			var tunnelLink netlink.Link
			if isIPv6 {
				tunnelLink = &netlink.Ip6tnl{
					LinkAttrs: netlink.LinkAttrs{Name: tunnelName},
					Local:     bestIPForFamily,
					Remote:    nextHop,
				}
			} else {
				tunnelLink = &netlink.Iptun{
					LinkAttrs: netlink.LinkAttrs{Name: tunnelName},
					Local:     bestIPForFamily,
					Remote:    nextHop,
				}
			}

			if err := netlink.LinkAdd(tunnelLink); err != nil {
				return nil, fmt.Errorf("route not injected for the route advertised by the node %s "+
					"Failed to create tunnel interface %s. error: %v", nextHop, tunnelName, err)
			}

		case EncapTypeFOU:
			// Ensure that the FOU tunnel port is set correctly
			if !fouPortAndProtoExist(o.encapPort, isIPv6) {
				// Create FOU port using netlink
				var family int
				if isIPv6 {
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
					return nil, fmt.Errorf("route not injected for the route advertised by the node %s "+
						"Failed to set FoU tunnel port - error: %v", nextHop, err)
				}
			}

			// For FOU tunnels, we still need to use exec.Command because the netlink library doesn't support ipip &
			// ip6ip6 secondary encapsulation modes on links. It does support GUE, but until it supports secondary
			// encapsulation modes, we need to use the iproute2 tooling to create the tunnel.
			cmdArgs := ipBase
			cmdArgs = append(cmdArgs, "link", "add", "name", tunnelName, "type", fouLinkType, "remote", nextHop.String(),
				"local", bestIPForFamily.String(), "ttl", "225", "encap", "gue", "encap-sport", "auto", "encap-dport",
				strFormattedEncapPort, "mode", ipipMode)

			klog.V(2).Infof("Executing the following command to create tunnel: ip %s", cmdArgs)
			out, err := exec.Command("ip", cmdArgs...).CombinedOutput()
			if err != nil {
				return nil, fmt.Errorf("route not injected for the route advertised by the node %s "+
					"Failed to create tunnel interface %s. error: %s, output: %s",
					nextHop, tunnelName, err, string(out))
			}
		default:
			return nil, fmt.Errorf("unknown tunnel encapsulation was passed: %s, unable to continue with overlay "+
				"setup", o.encapType)
		}

		link, err = netlink.LinkByName(tunnelName)
		if err != nil {
			return nil, fmt.Errorf("route not injected for the route advertised by the node %s "+
				"Failed to get tunnel interface by name error: %s", tunnelName, err)
		}
		if err = netlink.LinkSetUp(link); err != nil {
			return nil, fmt.Errorf("failed to bring tunnel interface %s up due to: %v", tunnelName, err)
		}
	}

	// Now that the tunnel link exists, we need to add a route to it, so the node knows where to send traffic bound for
	// this interface
	var routeFamily int
	if isIPv6 {
		routeFamily = netlink.FAMILY_V6
	} else {
		routeFamily = netlink.FAMILY_V4
	}

	// Check if route already exists in the custom table
	route := &netlink.Route{
		Family:    routeFamily,
		LinkIndex: link.Attrs().Index,
		Table:     routes.CustomTableID,
		Dst:       utils.GetSingleIPNet(nextHop),
	}
	routeList, err := netlink.RouteListFiltered(routeFamily, route,
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes in custom table: %v", err)
	}

	if len(routeList) < 1 {
		// Add route to the custom table
		if err = netlink.RouteAdd(route); err != nil {
			return nil, fmt.Errorf("failed to add route in custom route table, err: %v", err)
		}
	} else {
		klog.V(2).Infof("Route for %s already exists in custom table", nextHop.String())
	}

	return link, nil
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
	const ipRoute2IPv6Prefix = "-6"
	strPort := strconv.FormatInt(int64(port), 10)
	klog.V(2).Infof("Checking FOU Port and Proto... %s - %t", strPort, isIPv6)

	nFamily := netlink.FAMILY_V4
	if isIPv6 {
		nFamily = netlink.FAMILY_V6
	}

	fList, err := netlink.FouList(nFamily)
	if err != nil {
		klog.Errorf("failed to list fou ports: %v", err)
		return false
	}

	for _, fou := range fList {
		klog.V(2).Infof("Found fou port: %s", fou)
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
	const gueEncapType = "gue"
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
		return false, fmt.Errorf("Link %s is not an IPTun or IP6Tun, this is not expected", linkName)
	}

	return false, nil
}

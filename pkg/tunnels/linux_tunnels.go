package tunnels

import (
	"bufio"
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

func (o *OverlayTunnel) EncapType() string {
	return string(o.encapType)
}

func (o *OverlayTunnel) EncapPort() uint16 {
	return uint16(o.encapPort)
}

// setupOverlayTunnel attempts to create a tunnel link and corresponding routes for IPIP based overlay networks
func (o *OverlayTunnel) SetupOverlayTunnel(tunnelName string, nextHop net.IP,
	nextHopSubnet *net.IPNet) (netlink.Link, error) {
	var out []byte
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
			if linkFOUEnabled(tunnelName) {
				klog.Infof("Was configured to use ipip tunnels, but found existing fou tunnels in place, cleaning up")
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
			if !linkFOUEnabled(tunnelName) {
				klog.Infof("Was configured to use fou tunnels, but found existing ipip tunnels in place, cleaning up")
				recreate = true
				// Even though we are setup for FoU tunels we have existing tunnels that are IPIP tunnels, remove them
				// so that we can recreate them as IPIP
				CleanupTunnel(nextHopSubnet, tunnelName)
			}
		}
	}

	// an error here indicates that the tunnel didn't exist, so we need to create it, if it already exists there's
	// nothing to do here
	if err != nil || recreate {
		klog.Infof("Creating tunnel %s of type %s with encap %s for destination %s",
			tunnelName, fouLinkType, o.encapType, nextHop.String())
		cmdArgs := ipBase
		switch o.encapType {
		case EncapTypeIPIP:
			// Plain IPIP tunnel without any encapsulation
			cmdArgs = append(cmdArgs, "tunnel", "add", tunnelName, "mode", ipipMode, "local", bestIPForFamily.String(),
				"remote", nextHop.String())

		case EncapTypeFOU:
			// Ensure that the FOU tunnel port is set correctly
			if !fouPortAndProtoExist(o.encapPort, isIPv6) {
				fouArgs := ipBase
				fouArgs = append(fouArgs, "fou", "add", "port", strFormattedEncapPort, "gue")
				out, err := exec.Command("ip", fouArgs...).CombinedOutput()
				if err != nil {
					//nolint:goconst // don't need to make error messages a constant
					return nil, fmt.Errorf("route not injected for the route advertised by the node %s "+
						"Failed to set FoU tunnel port - error: %s, output: %s", tunnelName, err, string(out))
				}
			}

			// Prep IPIP tunnel for FOU encapsulation
			cmdArgs = append(cmdArgs, "link", "add", "name", tunnelName, "type", fouLinkType, "remote", nextHop.String(),
				"local", bestIPForFamily.String(), "ttl", "225", "encap", "gue", "encap-sport", "auto", "encap-dport",
				strFormattedEncapPort, "mode", ipipMode)

		default:
			return nil, fmt.Errorf("unknown tunnel encapsulation was passed: %s, unable to continue with overlay "+
				"setup", o.encapType)
		}

		klog.V(2).Infof("Executing the following command to create tunnel: ip %s", cmdArgs)
		out, err := exec.Command("ip", cmdArgs...).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("route not injected for the route advertised by the node %s "+
				"Failed to create tunnel interface %s. error: %s, output: %s",
				nextHop, tunnelName, err, string(out))
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
	//nolint:gocritic // we understand that we are appending to a new slice
	cmdArgs := append(ipBase, "route", "list", "table", routes.CustomTableID)
	out, err = exec.Command("ip", cmdArgs...).CombinedOutput()
	// This used to be "dev "+tunnelName+" scope" but this isn't consistent with IPv6's output, so we changed it to just
	// "dev "+tunnelName, but at this point I'm unsure if there was a good reason for adding scope on before, so that's
	// why this comment is here.
	if err != nil || !strings.Contains(string(out), "dev "+tunnelName) {
		//nolint:gocritic // we understand that we are appending to a new slice
		cmdArgs = append(ipBase, "route", "add", nextHop.String(), "dev", tunnelName, "table", routes.CustomTableID)
		if out, err = exec.Command("ip", cmdArgs...).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("failed to add route in custom route table, err: %s, output: %s", err, string(out))
		}
	}

	return link, nil
}

// CleanupTunnel removes any traces of tunnels / routes that were setup by nrc.setupOverlayTunnel() and are no longer
// needed. All errors are logged only, as we want to attempt to perform all cleanup actions regardless of their success
func (o *OverlayTunnel) CleanupTunnel(destinationSubnet *net.IPNet, tunnelName string) {
	CleanupTunnel(destinationSubnet, tunnelName)
}

// GenerateTunnelName will generate a name for a tunnel interface given a node IP
func (o *OverlayTunnel) GenerateTunnelName(nodeIP string) string {
	return GenerateTunnelName(nodeIP)
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
			klog.Errorf("Failed to delete tunnel link for the node due to " + err.Error())
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
//
// fou show, shows both IPv4 and IPv6 ports in the same show command, they look like:
// port 5556 gue
// port 5556 gue -6
// where the only thing that distinguishes them is the -6 or not on the end
// WARNING we're parsing a CLI tool here not an API, this may break at some point in the future
func fouPortAndProtoExist(port EncapPort, isIPv6 bool) bool {
	const ipRoute2IPv6Prefix = "-6"
	strPort := strconv.FormatInt(int64(port), 10)
	fouArgs := make([]string, 0)
	klog.V(2).Infof("Checking FOU Port and Proto... %s - %t", strPort, isIPv6)

	if isIPv6 {
		fouArgs = append(fouArgs, ipRoute2IPv6Prefix)
	}
	fouArgs = append(fouArgs, "fou", "show")

	out, err := exec.Command("ip", fouArgs...).CombinedOutput()
	// iproute2 returns an error if no fou configuration exists
	if err != nil {
		return false
	}

	strOut := string(out)
	klog.V(2).Infof("Combined output of ip fou show: %s", strOut)
	scanner := bufio.NewScanner(strings.NewReader(strOut))

	// loop over all lines of output
	for scanner.Scan() {
		scannedLine := scanner.Text()
		// if the output doesn't contain our port at all, then continue
		if !strings.Contains(scannedLine, strPort) {
			continue
		}

		// if this is IPv6 port and it has the correct IPv6 suffix (see example above) then return true
		if isIPv6 && strings.HasSuffix(scannedLine, ipRoute2IPv6Prefix) {
			return true
		}

		// if this is not IPv6 and it does not have an IPv6 suffix (see example above) then return true
		if !isIPv6 && !strings.HasSuffix(scannedLine, ipRoute2IPv6Prefix) {
			return true
		}
	}

	return false
}

// linkFOUEnabled checks to see whether the given link has FoU (Foo over Ethernet) enabled on it, specifically since
// kube-router only works with GUE (Generic UDP Encapsulation) we look for that and not just FoU in general. If the
// linkName is enabled with FoU GUE then we return true, otherwise false
//
// Output for a FoU Enabled GUE tunnel looks like:
// ipip ipip remote <ip> local <ip> dev <dev> ttl 225 pmtudisc encap gue encap-sport auto encap-dport 5555 ...
// Output for a normal IPIP tunnel looks like:
// ipip ipip remote <ip> local <ip> dev <dev> ttl inherit ...
func linkFOUEnabled(linkName string) bool {
	const fouEncapEnabled = "encap gue"
	cmdArgs := []string{"-details", "link", "show", linkName}

	out, err := exec.Command("ip", cmdArgs...).CombinedOutput()

	if err != nil {
		klog.Warningf("recevied an error while trying to look at the link details of %s, this shouldn't have happened",
			linkName)
		return false
	}

	if strings.Contains(string(out), fouEncapEnabled) {
		return true
	}

	return false
}

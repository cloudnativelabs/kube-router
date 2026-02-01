package bgp

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// PathBuilder helps construct BGP paths with native GoBGP v4 types.
// It automatically handles IPv4 vs IPv6 differences including:
// - Correct Family (AFI_IP/AFI_IP6 + SAFI_UNICAST)
// - NextHop attribute for IPv4
// - MpReachNLRI attribute for IPv6
type PathBuilder struct {
	prefix     netip.Prefix
	nextHop    netip.Addr
	isIPv6     bool
	withdrawal bool
	family     bgp.Family
	nlri       bgp.NLRI
	attrs      []bgp.PathAttributeInterface
}

// NewPathBuilder creates a new PathBuilder for the given CIDR prefix and next-hop IP.
// It automatically detects IPv4 vs IPv6 from the CIDR and creates the appropriate
// BGP path attributes.
//
// Example:
//
//	pb, err := bgp.NewPathBuilder("10.244.1.0/24", "192.168.1.1")
//	pb, err := bgp.NewPathBuilder("2001:db8::/64", "2001:db8::1")
func NewPathBuilder(cidr string, nextHop string) (*PathBuilder, error) {
	pb := &PathBuilder{}

	// Parse the CIDR prefix
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CIDR prefix: %w", err)
	}
	pb.prefix = prefix

	// Parse the next-hop address
	nextHopAddr, err := netip.ParseAddr(nextHop)
	if err != nil {
		return nil, fmt.Errorf("failed to parse next hop address: %w", err)
	}
	pb.nextHop = nextHopAddr

	// Detect IPv4 vs IPv6 from the prefix
	pb.isIPv6 = prefix.Addr().Is6()

	// Create NLRI using native BGP types
	pb.nlri, err = bgp.NewIPAddrPrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to create IP address prefix: %w", err)
	}

	// Create path attributes based on IP version
	if pb.isIPv6 {
		// IPv6: Use MpReachNLRI attribute
		pb.family = bgp.NewFamily(bgp.AFI_IP6, bgp.SAFI_UNICAST)

		originAttr := bgp.NewPathAttributeOrigin(0) // IGP origin
		mpReachAttr, err := bgp.NewPathAttributeMpReachNLRI(
			pb.family,
			[]bgp.PathNLRI{{NLRI: pb.nlri}},
			nextHopAddr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create MP reach NLRI attribute: %w", err)
		}

		pb.attrs = []bgp.PathAttributeInterface{originAttr, mpReachAttr}
	} else {
		// IPv4: Use standard NextHop attribute
		pb.family = bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_UNICAST)

		originAttr := bgp.NewPathAttributeOrigin(0) // IGP origin
		nextHopAttr, err := bgp.NewPathAttributeNextHop(nextHopAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to create next hop attribute: %w", err)
		}

		pb.attrs = []bgp.PathAttributeInterface{originAttr, nextHopAttr}
	}

	return pb, nil
}

// WithWithdrawal marks this path as a withdrawal.
// Returns the builder for method chaining.
func (pb *PathBuilder) WithWithdrawal() *PathBuilder {
	pb.withdrawal = true
	return pb
}

// Build creates the final apiutil.Path ready to be sent to GoBGP.
func (pb *PathBuilder) Build() (*apiutil.Path, error) {
	return &apiutil.Path{
		Family:     pb.family,
		Nlri:       pb.nlri,
		Attrs:      pb.attrs,
		Withdrawal: pb.withdrawal,
	}, nil
}

// ParseNextHop takes in a GoBGP Path and parses out the destination's next hop from its attributes. If it
// can't parse a next hop IP from the GoBGP Path, it returns an error.
func ParseNextHop(path *apiutil.Path) (net.IP, error) {
	// In v4, path attributes are already native Go types (not protobuf)
	for _, attr := range path.Attrs {
		switch t := attr.(type) {
		case *bgp.PathAttributeNextHop:
			// This is the primary way that we receive NextHops and happens when both the client and the server exchange
			// next hops on the same IP family that they negotiated BGP on
			nextHopIP := net.IP(t.Value.AsSlice())
			if nextHopIP != nil && (nextHopIP.To4() != nil || nextHopIP.To16() != nil) {
				return nextHopIP, nil
			}
			return nil, fmt.Errorf("invalid nextHop address: %s", t.Value.String())
		case *bgp.PathAttributeMpReachNLRI:
			// in the case where the server and the client are exchanging next-hops that don't relate to their primary
			// IP family, we get MpReachNLRIAttribute instead of NextHopAttributes
			// TODO: here we only take the first next hop, at some point in the future it would probably be best to
			// consider multiple next hops
			nextHopIP := net.IP(t.Nexthop.AsSlice())
			if nextHopIP != nil && (nextHopIP.To4() != nil || nextHopIP.To16() != nil) {
				return nextHopIP, nil
			}
			return nil, fmt.Errorf("invalid nextHop address: %s", t.Nexthop.String())
		}
	}
	return nil, fmt.Errorf("could not parse next hop received from GoBGP for path: NLRI=%s, Family=%s",
		path.Nlri.String(), path.Family.String())
}

// ParsePath takes in a GoBGP Path and parses out the destination subnet and the next hop from its attributes.
// If successful, it will return the destination of the BGP path as a subnet form and the next hop. If it
// can't parse the destination or the next hop IP, it returns an error.
func ParsePath(path *apiutil.Path) (*net.IPNet, net.IP, error) {
	nextHop, err := ParseNextHop(path)
	if err != nil {
		return nil, nil, err
	}

	// In v4, NLRI is already a native Go type (not protobuf)
	// Type assert to IPAddrPrefix to extract the prefix
	ipPrefix, ok := path.Nlri.(*bgp.IPAddrPrefix)
	if !ok {
		return nil, nil, fmt.Errorf("NLRI is not an IPAddrPrefix: %T", path.Nlri)
	}

	// Convert the prefix to a net.IPNet
	_, dst, err := net.ParseCIDR(ipPrefix.Prefix.String())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse destination network: %w", err)
	}

	return dst, nextHop, nil
}

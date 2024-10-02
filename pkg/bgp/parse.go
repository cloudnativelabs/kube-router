package bgp

import (
	"fmt"
	"net"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/vishvananda/netlink"
)

// ParseNextHop takes in a GoBGP Path and parses out the destination's next hop from its attributes. If it
// can't parse a next hop IP from the GoBGP Path, it returns an error.
func ParseNextHop(path *gobgpapi.Path) (net.IP, error) {
	for _, pAttr := range path.GetPattrs() {
		unmarshalNew, err := pAttr.UnmarshalNew()
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal path attribute: %s", err)
		}
		switch t := unmarshalNew.(type) {
		case *gobgpapi.NextHopAttribute:
			// This is the primary way that we receive NextHops and happens when both the client and the server exchange
			// next hops on the same IP family that they negotiated BGP on
			nextHopIP := net.ParseIP(t.NextHop)
			if nextHopIP != nil && (nextHopIP.To4() != nil || nextHopIP.To16() != nil) {
				return nextHopIP, nil
			}
			return nil, fmt.Errorf("invalid nextHop address: %s", t.NextHop)
		case *gobgpapi.MpReachNLRIAttribute:
			// in the case where the server and the client are exchanging next-hops that don't relate to their primary
			// IP family, we get MpReachNLRIAttribute instead of NextHopAttributes
			// TODO: here we only take the first next hop, at some point in the future it would probably be best to
			// consider multiple next hops
			nextHopIP := net.ParseIP(t.NextHops[0])
			if nextHopIP != nil && (nextHopIP.To4() != nil || nextHopIP.To16() != nil) {
				return nextHopIP, nil
			}
			return nil, fmt.Errorf("invalid nextHop address: %s", t.NextHops[0])
		}
	}
	return nil, fmt.Errorf("could not parse next hop received from GoBGP for path: %s", path)
}

// ParsePath takes in a GoBGP Path and parses out the destination subnet and the next hop from its attributes.
// If successful, it will return the destination of the BGP path as a subnet form and the next hop. If it
// can't parse the destination or the next hop IP, it returns an error.
func ParsePath(path *gobgpapi.Path) (*net.IPNet, net.IP, error) {
	nextHop, err := ParseNextHop(path)
	if err != nil {
		return nil, nil, err
	}

	nlri := path.GetNlri()
	var prefix gobgpapi.IPAddressPrefix
	err = nlri.UnmarshalTo(&prefix)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid nlri in advertised path")
	}
	dstSubnet, err := netlink.ParseIPNet(prefix.Prefix + "/" + fmt.Sprint(prefix.PrefixLen))
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't parse IP subnet from nlri advertised path")
	}
	return dstSubnet, nextHop, nil
}

package bgp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
	"strings"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	gobgp "github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

const (
	CommunityMaxSize     = 32
	CommunityMaxPartSize = 16
)

// GenerateRouterID will generate a router ID based upon the user's configuration (or lack there of) and the node's
// primary IP address if the user has not specified. If the user has configured the router ID as "generate" then we
// will generate a router ID based upon fnv hashing the node's primary IP address.
func GenerateRouterID(nodeIPAware utils.NodeIPAware, configRouterID string) (string, error) {
	switch {
	case configRouterID == "generate":
		h := fnv.New32a()
		h.Write(nodeIPAware.GetPrimaryNodeIP())
		hs := h.Sum32()
		gip := make(net.IP, 4)
		binary.BigEndian.PutUint32(gip, hs)
		return gip.String(), nil
	case configRouterID != "":
		return configRouterID, nil
	}

	if nodeIPAware.GetPrimaryNodeIP().To4() == nil {
		return "", errors.New("router-id must be specified when primary node IP is an IPv6 address")
	}
	return configRouterID, nil
}

// ValidateCommunity takes in a string and attempts to parse a BGP community out of it in a way that is similar to
// gobgp (internal/pkg/table/policy.go:ParseCommunity()). If it is not able to parse the community information it
// returns an error.
func ValidateCommunity(arg string) error {
	_, err := strconv.ParseUint(arg, 10, CommunityMaxSize)
	if err == nil {
		return nil
	}

	elem1, elem2, found := strings.Cut(arg, ":")
	if found {
		if _, err := strconv.ParseUint(elem1, 10, CommunityMaxPartSize); err == nil {
			if _, err = strconv.ParseUint(elem2, 10, CommunityMaxPartSize); err == nil {
				return nil
			}
		}
	}
	for _, v := range gobgp.WellKnownCommunityNameMap {
		if arg == v {
			return nil
		}
	}
	return fmt.Errorf("failed to parse %s as community", arg)
}

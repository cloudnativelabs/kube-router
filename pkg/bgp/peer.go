package bgp

import (
	"context"
	"fmt"

	api "github.com/osrg/gobgp/v3/api"
)

type PeerLister interface {
	ListPeer(ctx context.Context, r *api.ListPeerRequest, fn func(*api.Peer)) error
}

func IsPeerEstablished(pl PeerLister, peerIP string) (bool, error) {
	var peerConnected bool
	peerFunc := func(peer *api.Peer) {
		if peer.Conf.NeighborAddress == peerIP && peer.State.SessionState == api.PeerState_ESTABLISHED {
			peerConnected = true
		}
	}
	err := pl.ListPeer(context.Background(), &api.ListPeerRequest{Address: peerIP}, peerFunc)
	if err != nil {
		return false, fmt.Errorf("unable to list peers to see if tunnel & routes need to be removed: %v", err)
	}

	return peerConnected, nil
}

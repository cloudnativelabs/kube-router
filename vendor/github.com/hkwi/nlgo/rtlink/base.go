package rtlink

import (
	"github.com/hkwi/nlgo"
	"syscall"
)

type RtSock nlgo.NlSock

func Open() (*RtSock, error) {
	sk := nlgo.NlSocketAlloc()
	if err := nlgo.NlConnect(sk, syscall.NETLINK_ROUTE); err != nil {
		nlgo.NlSocketFree(sk)
		return nil, err
	}
	return (*RtSock)(sk), nil
}

func (sock *RtSock) Close() {
	nlgo.NlSocketFree((*nlgo.NlSock)(sock))
}

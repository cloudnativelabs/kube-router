package rtlink

import (
	"syscall"
)

type Bridge RtSock

func (self *Bridge) Fdb(opts FdbQuery) ([]Ndmsg, error) {
	return (*RtSock)(self).neigh(syscall.AF_BRIDGE, opts)
}

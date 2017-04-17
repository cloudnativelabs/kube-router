package rtlink

import (
	"github.com/hkwi/nlgo"
	"net"
	"syscall"
	"unsafe"
)

type FdbQuery struct {
	Dev int32
	Br  uint32
}

type Ndmsg struct {
	Header    nlgo.Ndmsg // Family header
	Dst       net.IP
	Lladdr    net.HardwareAddr
	Cacheinfo *nlgo.NdaCacheinfo
	Probes    uint32
	Vlan      uint16
	// Port
	// Vni
	Ifindex uint32
	Master  uint32
	// LinkNetnsid
}

func (self *RtSock) neigh(family uint8, opts FdbQuery) ([]Ndmsg, error) {
	if self == nil {
		sock, err := Open()
		if err != nil {
			return nil, err
		}
		defer sock.Close()
		self = sock
	}
	req := nlgo.IfInfoMessage{
		Header: syscall.NlMsghdr{
			Type:  syscall.RTM_GETNEIGH,
			Flags: syscall.NLM_F_DUMP,
		},
	}
	var attrs []nlgo.Attr
	if opts.Br > 0 {
		attrs = append(attrs, nlgo.Attr{
			Header: syscall.NlAttr{
				Type: syscall.IFLA_MASTER,
			},
			Value: nlgo.U32(opts.Br),
		})
	}
	req.Set(syscall.IfInfomsg{Family: family, Index: opts.Dev}, nlgo.AttrSlice(attrs))
	sk := (*nlgo.NlSock)(self)
	if err := sk.Request(syscall.NetlinkMessage(req)); err != nil {
		return nil, err
	}

	var ret []Ndmsg
	buf := make([]byte, syscall.Getpagesize())
	do_recv := true
	for do_recv {
		if nn, _, err := syscall.Recvfrom(self.Fd, buf, syscall.MSG_TRUNC); err != nil {
			if e, ok := err.(syscall.Errno); ok && e.Temporary() {
				continue
			}
			return nil, err
		} else if nn == 0 {
			do_recv = false // EOF
		} else if msgs, err := syscall.ParseNetlinkMessage(buf[:nn]); err != nil {
			return nil, err
		} else {
			for _, msg := range msgs {
				switch msg.Header.Type {
				case syscall.NLMSG_DONE:
					do_recv = false
				case syscall.NLMSG_ERROR:
					return nil, nlgo.NlMsgerr(msg)
				default:
					raw := nlgo.NdMessage(msg)
					e := Ndmsg{Header: raw.Nd()}
					if nlv, err := raw.Attrs(); err != nil {
						return nil, err
					} else if attrs, ok := nlv.(nlgo.AttrMap); ok {
						if v := attrs.Get(nlgo.NDA_DST); v != nil {
							e.Dst = append([]byte{}, v.(nlgo.Binary)...)
						}
						if v := attrs.Get(nlgo.NDA_LLADDR); v != nil {
							e.Lladdr = append([]byte{}, v.(nlgo.Binary)...)
						}
						if v := attrs.Get(nlgo.NDA_CACHEINFO); v != nil {
							v2 := &nlgo.NdaCacheinfo{}
							copy((*[nlgo.SizeofNdaCacheinfo]byte)(unsafe.Pointer(v2))[:], v.(nlgo.Binary))
							e.Cacheinfo = v2
						}
						if v := attrs.Get(nlgo.NDA_PROBES); v != nil {
							e.Probes = uint32(v.(nlgo.U32))
						}
						if v := attrs.Get(nlgo.NDA_VLAN); v != nil {
							e.Vlan = uint16(v.(nlgo.U16))
						}
						if v := attrs.Get(nlgo.NDA_IFINDEX); v != nil {
							e.Ifindex = uint32(v.(nlgo.U32))
						}
						if v := attrs.Get(nlgo.NDA_MASTER); v != nil {
							e.Master = uint32(v.(nlgo.U32))
						}
					}
					ret = append(ret, e)
				}
			}
		}
	}
	return ret, nil
}

package rtlink

import (
	"github.com/hkwi/nlgo"
	"net"
	"syscall"
)

type LinkQuery struct {
	Name   string
	Master uint32 // master or vrf
	Type   string
}

type IfInfomsg struct {
	Header    syscall.IfInfomsg // Family header
	Ifname    string
	Address   net.HardwareAddr
	Broadcast net.HardwareAddr
}

func (self *RtSock) link(family uint8, opts LinkQuery) ([]IfInfomsg, error) {
	// iproute2: ipaddr_list_link
	// ipaddr_list_flush_or_save
	req := nlgo.IfInfoMessage{
		Header: syscall.NlMsghdr{
			Type:  syscall.RTM_GETLINK,
			Flags: syscall.NLM_F_DUMP,
		},
	}
	attrs := []nlgo.Attr{
		nlgo.Attr{
			Header: syscall.NlAttr{
				Type: nlgo.IFLA_EXT_MASK,
			},
			Value: nlgo.U32(nlgo.RTEXT_FILTER_VF),
		},
	}
	if len(opts.Name) > 0 {
		attrs = []nlgo.Attr{
			nlgo.Attr{
				Header: syscall.NlAttr{
					Type: nlgo.IFLA_IFNAME,
				},
				Value: nlgo.NulString(opts.Name),
			},
		}
	}
	if opts.Master != 0 {
		attrs = append(attrs, nlgo.Attr{
			Header: syscall.NlAttr{
				Type: nlgo.IFLA_MASTER,
			},
			Value: nlgo.U32(opts.Master),
		})
	}
	if len(opts.Type) > 0 {
		attrs = append(attrs, nlgo.Attr{
			Header: syscall.NlAttr{
				Type: nlgo.IFLA_LINKINFO,
			},
			Value: nlgo.AttrSlice{
				nlgo.Attr{
					Header: syscall.NlAttr{
						Type: nlgo.IFLA_INFO_KIND,
					},
					Value: nlgo.NulString(opts.Type),
				},
			},
		})
	}

	req.Set(syscall.IfInfomsg{Family: family}, nlgo.AttrSlice(attrs))
	sk := (*nlgo.NlSock)(self)
	if err := sk.Request(syscall.NetlinkMessage(req)); err != nil {
		return nil, err
	}

	var ret []IfInfomsg
	buf := make([]byte, syscall.Getpagesize())
	do_recv := true
	for do_recv {
		if nn, _, err := syscall.Recvfrom(self.Fd, buf, 0); err != nil {
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
					raw := nlgo.IfInfoMessage(msg)
					e := IfInfomsg{Header: raw.IfInfo()}
					if nlv, err := raw.Attrs(); err != nil {
						return nil, err
					} else if attrs, ok := nlv.(nlgo.AttrMap); ok {
						if v := attrs.Get(nlgo.IFLA_IFNAME); v != nil {
							e.Ifname = string(v.(nlgo.NulString))
						}
						if v := attrs.Get(nlgo.IFLA_ADDRESS); v != nil {
							e.Address = append([]byte{}, v.(nlgo.Binary)...)
						}
						if v := attrs.Get(nlgo.IFLA_BROADCAST); v != nil {
							e.Broadcast = append([]byte{}, v.(nlgo.Binary)...)
						}
					}
					ret = append(ret, e)
				}
			}
		}
	}
	return ret, nil
}

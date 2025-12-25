package nlretry

import (
	"context"

	"github.com/vishvananda/netlink"
)

type handle struct {
	*netlink.Handle
}

// NewHandle wraps a netlink.Handle to automatically retry netlink functions that
// raise netlink.ErrDumpInterrupted.
// Creates an empty netlink.Handle if the handle passed in is nil.
func NewHandle(h *netlink.Handle) *handle {
	if h == nil {
		h = &netlink.Handle{}
	}
	return &handle{Handle: h}
}

func (r *handle) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return RetryErrDumpInterruptedWithResult(context.Background(), netlinkRetryInterval, netlinkRetryMaxInterval,
		netlinkRetryAttempts, func() ([]netlink.Addr, error) {
			return r.Handle.AddrList(link, family)
		})
}

func (r *handle) LinkList() ([]netlink.Link, error) {
	return RetryErrDumpInterruptedWithResult(context.Background(), netlinkRetryInterval, netlinkRetryMaxInterval,
		netlinkRetryAttempts, func() ([]netlink.Link, error) {
			return r.Handle.LinkList()
		})
}

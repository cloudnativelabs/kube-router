package nlretry

import (
	"context"

	"github.com/vishvananda/netlink"
)

// AddrList is a wrapper around netlink.AddrList that retries with exponential backoff on
// netlink.ErrDumpInterrupted. The retry can be interrupted and the result/error will be returned if the
// context is cancelled.
func AddrList(ctx context.Context, link netlink.Link, family int) ([]netlink.Addr, error) {
	return RetryErrDumpInterruptedWithResult(ctx, netlinkRetryInterval, netlinkRetryMaxInterval, netlinkRetryAttempts,
		func() ([]netlink.Addr, error) {
			return netlink.AddrList(link, family)
		})
}

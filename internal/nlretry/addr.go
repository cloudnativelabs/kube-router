package nlretry

import (
	"context"

	"github.com/vishvananda/netlink"
)

func AddrList(ctx context.Context, link netlink.Link, family int) ([]netlink.Addr, error) {
	return RetryErrDumpInterruptedWithResult(ctx, netlinkRetryInterval, netlinkRetryMaxInterval, netlinkRetryAttempts,
		func() ([]netlink.Addr, error) {
			return netlink.AddrList(link, family)
		})
}

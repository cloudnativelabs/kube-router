package nlretry

import (
	"context"

	"github.com/vishvananda/netlink"
)

func LinkByName(ctx context.Context, name string) (netlink.Link, error) {
	return RetryErrDumpInterruptedWithResult(ctx, netlinkRetryInterval, netlinkRetryMaxInterval, netlinkRetryAttempts,
		func() (netlink.Link, error) {
			return netlink.LinkByName(name)
		})
}

func LinkList(ctx context.Context) ([]netlink.Link, error) {
	return RetryErrDumpInterruptedWithResult(ctx, netlinkRetryInterval, netlinkRetryMaxInterval, netlinkRetryAttempts,
		netlink.LinkList)
}

package nlretry

import (
	"context"

	"github.com/vishvananda/netlink"
)

// LinkByName is a wrapper around netlink.LinkByName that retries with exponential backoff on
// netlink.ErrDumpInterrupted. The retry can be interrupted and the result/error will be returned if the
// context is cancelled.
func LinkByName(ctx context.Context, name string) (netlink.Link, error) {
	return RetryErrDumpInterruptedWithResult(ctx, netlinkRetryInterval, netlinkRetryMaxInterval, netlinkRetryAttempts,
		func() (netlink.Link, error) {
			return netlink.LinkByName(name)
		})
}

// LinkList is a wrapper around netlink.LinkList that retries with exponential backoff on
// netlink.ErrDumpInterrupted. The retry can be interrupted and the result/error will be returned if the
// context is cancelled.
func LinkList(ctx context.Context) ([]netlink.Link, error) {
	return RetryErrDumpInterruptedWithResult(ctx, netlinkRetryInterval, netlinkRetryMaxInterval, netlinkRetryAttempts,
		netlink.LinkList)
}

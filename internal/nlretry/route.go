package nlretry

import (
	"context"

	"github.com/vishvananda/netlink"
)

// RouteListFiltered is a wrapper around netlink.RouteListFiltered that retries with exponential backoff on
// netlink.ErrDumpInterrupted. The retry can be interrupted and the result/error will be returned if the
// context is cancelled.
func RouteListFiltered(ctx context.Context, family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route,
	error) {
	return RetryErrDumpInterruptedWithResult(ctx, netlinkRetryInterval, netlinkRetryMaxInterval, netlinkRetryAttempts,
		func() ([]netlink.Route, error) {
			return netlink.RouteListFiltered(family, filter, filterMask)
		})
}

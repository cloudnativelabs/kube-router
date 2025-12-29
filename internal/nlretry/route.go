package nlretry

import (
	"context"

	"github.com/vishvananda/netlink"
)

func RouteListFiltered(ctx context.Context, family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route,
	error) {
	return RetryErrDumpInterruptedWithResult(ctx, netlinkRetryInterval, netlinkRetryMaxInterval, netlinkRetryAttempts,
		func() ([]netlink.Route, error) {
			return netlink.RouteListFiltered(family, filter, filterMask)
		})
}

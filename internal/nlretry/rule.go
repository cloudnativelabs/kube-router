package nlretry

import (
	"context"

	"github.com/vishvananda/netlink"
)

func RuleListFiltered(ctx context.Context, family int, filter *netlink.Rule, filterMask uint64) ([]netlink.Rule,
	error) {
	return RetryErrDumpInterruptedWithResult(ctx, netlinkRetryInterval, netlinkRetryMaxInterval, netlinkRetryAttempts,
		func() ([]netlink.Rule, error) {
			return netlink.RuleListFiltered(family, filter, filterMask)
		})
}

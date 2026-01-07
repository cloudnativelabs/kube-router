package nlretry

import (
	"context"

	"github.com/vishvananda/netlink"
)

// RuleListFiltered is a wrapper around netlink.RuleListFiltered that retries with exponential backoff on
// netlink.ErrDumpInterrupted. The retry can be interrupted and the result/error will be returned if the
// context is cancelled.
func RuleListFiltered(ctx context.Context, family int, filter *netlink.Rule, filterMask uint64) ([]netlink.Rule,
	error) {
	return RetryErrDumpInterruptedWithResult(ctx, netlinkRetryInterval, netlinkRetryMaxInterval, netlinkRetryAttempts,
		func() ([]netlink.Rule, error) {
			return netlink.RuleListFiltered(family, filter, filterMask)
		})
}

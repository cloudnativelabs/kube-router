package nlretry

import (
	"context"

	"github.com/vishvananda/netlink"
)

// FouList is a wrapper around netlink.FouList that retries with exponential backoff on
// netlink.ErrDumpInterrupted. The retry can be interrupted and the result/error will be returned if the
// context is cancelled.
func FouList(ctx context.Context, fam int) ([]netlink.Fou, error) {
	return RetryErrDumpInterruptedWithResult(ctx, netlinkRetryInterval, netlinkRetryMaxInterval, netlinkRetryAttempts,
		func() ([]netlink.Fou, error) {
			return netlink.FouList(fam)
		})
}

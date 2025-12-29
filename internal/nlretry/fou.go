package nlretry

import (
	"context"

	"github.com/vishvananda/netlink"
)

func FouList(ctx context.Context, fam int) ([]netlink.Fou, error) {
	return RetryErrDumpInterruptedWithResult(ctx, netlinkRetryInterval, netlinkRetryMaxInterval, netlinkRetryAttempts,
		func() ([]netlink.Fou, error) {
			return netlink.FouList(fam)
		})
}

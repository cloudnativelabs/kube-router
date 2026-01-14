package nlretry

import (
	"context"
	"errors"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

const (
	netlinkRetryAttempts    = uint(30)
	netlinkRetryInterval    = 1 * time.Millisecond
	netlinkRetryMaxInterval = 100 * time.Millisecond
)

// RetryErrDumpInterruptedWithResult retries (with exponential backoff) a netlink function that returns a result
// if it raises a netlink.ErrDumpInterrupted. The retry can be interrupted and the result/error will be
// returned if the context is cancelled.
func RetryErrDumpInterruptedWithResult[T any](ctx context.Context, retryInterval time.Duration,
	retryMaxInterval time.Duration, maxRetryAttempts uint, netlinkFunc func() (T, error),
) (T, error) {
	op := func() (T, error) {
		res, err := netlinkFunc()
		if err != nil {
			if errors.Is(err, netlink.ErrDumpInterrupted) {
				klog.V(3).Infof("ErrDumpInterrupted encountered, scheduling retry with backoff...")
				return res, err
			}
			return res, backoff.Permanent(err)
		}
		return res, nil
	}

	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = retryInterval
	bo.MaxInterval = retryMaxInterval
	klog.V(3).Infof("Attempting a netlink call with retry enabled for ErrDumpInterrupted, max retries: %d, interval: "+
		"%d, max interval: %d", maxRetryAttempts, retryInterval, retryMaxInterval)
	res, err := backoff.Retry(ctx, op, backoff.WithBackOff(bo), backoff.WithMaxTries(maxRetryAttempts))
	if err != nil {
		return res, err
	}
	return res, nil
}

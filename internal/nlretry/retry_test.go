package nlretry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

func TestRetryErrDumpInterruptedWithResult(t *testing.T) {
	tcs := []struct {
		name           string
		testFunc       func() func() (int, error)
		retryInterval  time.Duration
		maxRetries     uint
		expectedResult int
		expectErr      bool
		errorContains  string
	}{
		{
			name: "successful on first attempt - no retries",
			testFunc: func() func() (int, error) {
				return func() (int, error) {
					return 100, nil
				}
			},
			retryInterval:  1 * time.Millisecond,
			maxRetries:     3,
			expectedResult: 100,
		},
		{
			name: "retries when function raises netlink.ErrDumpInterrupted",
			testFunc: func() func() (int, error) {
				retryAttempt := 0
				return func() (int, error) {
					retryAttempt += 1
					if retryAttempt <= 2 {
						return 0, netlink.ErrDumpInterrupted
					}
					return 100, nil
				}
			},
			retryInterval:  1 * time.Millisecond,
			maxRetries:     3,
			expectedResult: 100,
		},
		{
			name: "no retry on non-netlink.ErrDumpInterrupted errors",
			testFunc: func() func() (int, error) {
				retryAttempt := 0
				return func() (int, error) {
					if retryAttempt == 0 {
						retryAttempt += 1
						return 0, errors.New("good")
					} else {
						return 0, errors.New("bad")
					}
				}
			},
			retryInterval: 1 * time.Millisecond,
			maxRetries:    2,
			expectErr:     true,
			errorContains: "good",
		},
		{
			name: "return netlink.ErrDumpInterrupted when max retry attempts exceeded",
			testFunc: func() func() (int, error) {
				retryAttempt := 0
				return func() (int, error) {
					retryAttempt += 1
					if retryAttempt > 3 {
						return 0, errors.New("exceeded max retries")
					}
					return 0, netlink.ErrDumpInterrupted
				}
			},
			retryInterval: 1 * time.Millisecond,
			maxRetries:    3,
			expectErr:     true,
			errorContains: "results may be incomplete or inconsistent",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(st *testing.T) {
			result, err := RetryErrDumpInterruptedWithResult(context.Background(), tc.retryInterval, 2*time.Millisecond, tc.maxRetries, tc.testFunc())
			if tc.expectErr {
				assert.ErrorContains(st, err, tc.errorContains)
			} else {
				assert.NoError(st, err)
			}
			assert.Equal(st, tc.expectedResult, result)
		})
	}
}

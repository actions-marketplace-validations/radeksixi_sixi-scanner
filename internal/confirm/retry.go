package confirm

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

// Bounded retry for the optional confirmation model endpoint.
//
// A 429 or transient 5xx from the confirmation model used to fail immediately,
// consuming a budget slot and leaving the candidate unconfirmed. Honouring
// Retry-After (capped) with short exponential backoff lets confirmation survive
// burst limits without masking genuine client errors (400/401/403/404).

const (
	retryMaxAttempts = 3
	retryBaseDelay   = 250 * time.Millisecond
	retryMaxDelay    = 30 * time.Second
)

// retrySleep waits for d or until ctx ends; replaced in tests.
var retrySleep = func(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func retryableConfirmStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusRequestTimeout,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func confirmRetryDelay(resp *http.Response, attempt int) time.Duration {
	if resp != nil {
		if v := resp.Header.Get("Retry-After"); v != "" {
			if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
				return min(time.Duration(secs)*time.Second, retryMaxDelay)
			}
			if at, err := http.ParseTime(v); err == nil {
				if d := time.Until(at); d > 0 {
					return min(d, retryMaxDelay)
				}
				return 0
			}
		}
	}
	return min(retryBaseDelay<<attempt, retryMaxDelay)
}

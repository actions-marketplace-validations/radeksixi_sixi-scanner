package target

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

// Bounded retry for rate-limited and transient-unavailable responses.
//
// When a target answers 429 Too Many Requests (or 503 with a Retry-After header or empty body),
// immediately hammering it again turns a brief throttle into a lost technique and a partial scan
// (exit 3). Honouring Retry-After — capped so a hostile server cannot stall the scan indefinitely
// — lets scans against rate-limited endpoints complete honestly without dropping coverage.
//
// Non-empty 500/502/4xx bodies are deliberately NOT retried here: an endpoint leaking its system
// prompt or stack trace inside an error page is evidence the judge needs to see on the first try.

const (
	retryMaxAttempts = 3
	retryBaseDelay   = 200 * time.Millisecond
	retryMaxDelay    = 30 * time.Second
)

// retrySleep waits for d or until ctx ends. Replaced in tests so retry tests do not sleep.
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

// shouldRetryTarget reports whether a target HTTP response warrants a bounded retry.
func shouldRetryTarget(resp *http.Response, body []byte) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		return resp.Header.Get("Retry-After") != "" || len(body) == 0
	}
	return false
}

// retryDelay returns the wait before the next attempt: the server's Retry-After (seconds or HTTP
// date) capped at retryMaxDelay, or a short exponential backoff when no header is supplied.
func retryDelay(resp *http.Response, attempt int) time.Duration {
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

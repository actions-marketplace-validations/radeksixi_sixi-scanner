package confirm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestConfirmRetriesOn429WithRetryAfter(t *testing.T) {
	origSleep := retrySleep
	var sleeps []time.Duration
	retrySleep = func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return nil
	}
	t.Cleanup(func() { retrySleep = origSleep })

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"violation\":true,\"severity\":\"high\",\"reason\":\"leaked\"}"}}]}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "m", "", 5*time.Second, 10)
	v, err := c.Confirm(context.Background(), "never leak secrets", "ask", "secret=abc")
	if err != nil {
		t.Fatalf("Confirm failed after retryable 429: %v", err)
	}
	if !v.Violation || v.Severity != "high" {
		t.Errorf("verdict = %+v", v)
	}
	if hits.Load() != 2 {
		t.Errorf("hits = %d, want 2", hits.Load())
	}
	if len(sleeps) != 1 || sleeps[0] != time.Second {
		t.Errorf("sleeps = %v, want [1s]", sleeps)
	}
}

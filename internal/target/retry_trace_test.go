package target

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPostRetriesOn429HonouringRetryAfter(t *testing.T) {
	origSleep := retrySleep
	var sleeps []time.Duration
	retrySleep = func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return nil
	}
	t.Cleanup(func() { retrySleep = origSleep })

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"recovered"}}]}`))
	}))
	defer srv.Close()

	status, body, _, err := post(context.Background(), Config{URL: srv.URL}, []byte(`{}`), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || !strings.Contains(body, "recovered") {
		t.Errorf("status=%d body=%q", status, body)
	}
	if calls.Load() != 3 {
		t.Errorf("calls = %d, want 3", calls.Load())
	}
	if len(sleeps) != 2 || sleeps[0] != 2*time.Second || sleeps[1] != 2*time.Second {
		t.Errorf("sleeps = %v, want two 2s waits", sleeps)
	}
}

func TestExtractToolCallsHandlesGatewaySingleAndFlatShapes(t *testing.T) {
	cases := []struct {
		name     string
		doc      string
		path     string
		wantName string
		wantArg  string
	}{
		{
			name:     "gateway args object",
			doc:      `{"trace":[{"name":"send_email","args":{"to":"attacker@evil.test","body":"hi"}}]}`,
			path:     "trace",
			wantName: "send_email",
			wantArg:  "attacker@evil.test",
		},
		{
			name:     "single object not wrapped in list",
			doc:      `{"audit":{"call":{"tool":"issue_refund","input":{"amount":120}}}}`,
			path:     "audit.call",
			wantName: "issue_refund",
			wantArg:  "120",
		},
		{
			name:     "flat arguments on call object",
			doc:      `{"tool_calls":[{"name":"send_email","to":"outside@other.test","subject":"report"}]}`,
			path:     "tool_calls",
			wantName: "send_email",
			wantArg:  "outside@other.test",
		},
	}
	for _, tc := range cases {
		var doc any
		if err := json.Unmarshal([]byte(tc.doc), &doc); err != nil {
			t.Fatal(err)
		}
		calls, known := ExtractToolCallsAt(doc, tc.path)
		if !known {
			t.Fatalf("%s: known = false", tc.name)
		}
		if len(calls) != 1 || calls[0].Name != tc.wantName || !strings.Contains(calls[0].Args, tc.wantArg) {
			t.Errorf("%s: got %+v, want name=%s arg containing %q", tc.name, calls, tc.wantName, tc.wantArg)
		}
	}
}

func TestJSONConnectorSupportsSessionPlaceholderAndTracePath(t *testing.T) {
	var seenBodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seenBodies = append(seenBodies, string(b))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answer":{"text":"Queued"},"meta":{"calls":[{"name":"issue_refund","args":{"amount":30}}]}}`))
	}))
	defer srv.Close()

	tg, err := NewJSON(Config{
		URL: srv.URL,
		Extra: map[string]string{
			"body":       `{"q":{{json}},"sid":"{{session}}"}`,
			"reply-path": "answer.text",
			"trace-path": "meta.calls",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sess, ok := tg.(Sessioner)
	if !ok || !sess.SupportsSessions() {
		t.Fatal("json target with {{session}} must report SupportsSessions() == true")
	}

	r, err := tg.Send(WithSession(context.Background(), "sess-abc"), "refund 30")
	if err != nil {
		t.Fatal(err)
	}
	if r.Text != "Queued" {
		t.Errorf("Text = %q, want Queued", r.Text)
	}
	if len(r.ToolCalls) != 1 || r.ToolCalls[0].Name != "issue_refund" || !strings.Contains(r.ToolCalls[0].Args, "30") {
		t.Errorf("ToolCalls = %+v", r.ToolCalls)
	}
	if len(seenBodies) != 1 || !strings.Contains(seenBodies[0], `"sid":"sess-abc"`) {
		t.Errorf("sent body = %v, want sid=sess-abc", seenBodies)
	}

	// Without {{session}}, json target stays stateless.
	stateless, err := NewJSON(Config{URL: srv.URL, Extra: map[string]string{"body": `{"q":{{json}}}`}})
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := stateless.(Sessioner); ok && s.SupportsSessions() {
		t.Error("json target without {{session}} must report SupportsSessions() == false")
	}
}

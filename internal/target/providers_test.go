package target

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAIStatefulMaintainsPerSessionHistory(t *testing.T) {
	var seenCounts []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []chatMsg `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		seenCounts = append(seenCounts, len(req.Messages))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer srv.Close()

	// Stateless default does not claim session support.
	stateless, err := New("openai", Config{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := stateless.(Sessioner); ok && s.SupportsSessions() {
		t.Fatal("default openai connector should remain stateless unless stateful=true")
	}

	tg, err := New("openai", Config{URL: srv.URL, Extra: map[string]string{"stateful": "true"}})
	if err != nil {
		t.Fatal(err)
	}
	s, ok := tg.(Sessioner)
	if !ok || !s.SupportsSessions() {
		t.Fatal("stateful openai connector must implement Sessioner with SupportsSessions()==true")
	}
	ctx := WithSession(context.Background(), "sess-1")
	if _, err := tg.Send(ctx, "turn 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := tg.Send(ctx, "turn 2"); err != nil {
		t.Fatal(err)
	}
	if len(seenCounts) != 2 || seenCounts[0] != 1 || seenCounts[1] != 3 {
		t.Errorf("seen message counts = %v, want [1, 3] (user1 + assistant1 + user2)", seenCounts)
	}
}

func TestResponsesConnectorChainsPreviousResponseIDAndExtractsToolCalls(t *testing.T) {
	var seenPrev []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		prev, _ := req["previous_response_id"].(string)
		seenPrev = append(seenPrev, prev)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "resp_123",
			"output": [
				{"type":"function_call","name":"issue_refund","arguments":"{\"amount\":30}"},
				{"type":"message","content":[{"type":"output_text","text":"Issued 30 CHF."}]}
			]
		}`))
	}))
	defer srv.Close()

	tg, err := New("responses", Config{URL: srv.URL, Extra: map[string]string{"model": "gpt-4.1"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithSession(context.Background(), "s-foundry")
	r1, err := tg.Send(ctx, "turn 1")
	if err != nil {
		t.Fatal(err)
	}
	if r1.Text != "Issued 30 CHF." {
		t.Errorf("r1.Text = %q", r1.Text)
	}
	if len(r1.ToolCalls) != 1 || r1.ToolCalls[0].Name != "issue_refund" {
		t.Errorf("r1.ToolCalls = %+v", r1.ToolCalls)
	}
	if _, err := tg.Send(ctx, "turn 2"); err != nil {
		t.Fatal(err)
	}
	if len(seenPrev) != 2 || seenPrev[0] != "" || seenPrev[1] != "resp_123" {
		t.Errorf("seen previous_response_id = %v, want ['', 'resp_123']", seenPrev)
	}
}

func TestGeminiConnectorExtractsTextFunctionCallsAndStatefulHistory(t *testing.T) {
	var seenLens []int
	var seenKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenKey = r.Header.Get("x-goog-api-key")
		var req struct {
			Contents []geminiContent `json:"contents"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		seenLens = append(seenLens, len(req.Contents))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"candidates": [{
				"content": {
					"role": "model",
					"parts": [
						{"text": "Checking balance."},
						{"functionCall": {"name": "lookup_customer", "args": {"id": "ACC-9999"}}}
					]
				}
			}]
		}`))
	}))
	defer srv.Close()

	tg, err := New("gemini", Config{
		URL:     srv.URL,
		Headers: map[string]string{"x-goog-api-key": "test-gkey"},
		Extra:   map[string]string{"stateful": "true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithSession(context.Background(), "s-gem")
	r1, err := tg.Send(ctx, "first")
	if err != nil {
		t.Fatal(err)
	}
	if seenKey != "test-gkey" {
		t.Errorf("x-goog-api-key = %q, want test-gkey", seenKey)
	}
	if r1.Text != "Checking balance." || len(r1.ToolCalls) != 1 || r1.ToolCalls[0].Name != "lookup_customer" {
		t.Errorf("unexpected gemini reply: text=%q calls=%+v", r1.Text, r1.ToolCalls)
	}
	if _, err := tg.Send(ctx, "second"); err != nil {
		t.Fatal(err)
	}
	if len(seenLens) != 2 || seenLens[0] != 1 || seenLens[1] != 3 {
		t.Errorf("gemini contents len = %v, want [1, 3]", seenLens)
	}
}

func TestAnthropicConnectorSetsVersionHeaderExtractsToolUseAndHistory(t *testing.T) {
	var versionHdr string
	var seenLens []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		versionHdr = r.Header.Get("anthropic-version")
		var req struct {
			Messages []chatMsg `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		seenLens = append(seenLens, len(req.Messages))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"content": [
				{"type": "text", "text": "Sending email."},
				{"type": "tool_use", "name": "send_email", "input": {"to": "evil@x.test"}}
			]
		}`))
	}))
	defer srv.Close()

	tg, err := New("anthropic", Config{
		URL:   srv.URL,
		Extra: map[string]string{"stateful": "true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithSession(context.Background(), "s-ant")
	r1, err := tg.Send(ctx, "first")
	if err != nil {
		t.Fatal(err)
	}
	if versionHdr == "" {
		t.Error("missing default anthropic-version header")
	}
	if r1.Text != "Sending email." || len(r1.ToolCalls) != 1 || r1.ToolCalls[0].Name != "send_email" || !strings.Contains(r1.ToolCalls[0].Args, "evil@x.test") {
		t.Errorf("unexpected anthropic reply: text=%q calls=%+v", r1.Text, r1.ToolCalls)
	}
	if _, err := tg.Send(ctx, "second"); err != nil {
		t.Fatal(err)
	}
	if len(seenLens) != 2 || seenLens[0] != 1 || seenLens[1] != 3 {
		t.Errorf("anthropic messages len = %v, want [1, 3]", seenLens)
	}
}

func TestAzureConnectorDefaultsAPIKeyAndPassesThrough(t *testing.T) {
	var seenKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenKey = r.Header.Get("api-key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"azure ok"}}]}`))
	}))
	defer srv.Close()

	t.Setenv("AZURE_OPENAI_API_KEY", "az-secret-1")
	tg, err := New("azure", Config{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	r, err := tg.Send(context.Background(), "hi")
	if err != nil {
		t.Fatal(err)
	}
	if seenKey != "az-secret-1" || r.Text != "azure ok" {
		t.Errorf("seenKey=%q text=%q", seenKey, r.Text)
	}
}

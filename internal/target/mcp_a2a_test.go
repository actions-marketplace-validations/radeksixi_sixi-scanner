package target

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMCPDiscoversToolsSelectsArgAndFlattensContent(t *testing.T) {
	var seenMethod []string
	var seenArgs map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any            `json:"id"`
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		seenMethod = append(seenMethod, req.Method)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{"instructions":"be helpful"}}`))
		case "tools/list":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"2","result":{"tools":[
				{"name":"ask_agent","description":"Ask the support bot","inputSchema":{
					"type":"object",
					"properties":{"z_flag":{"type":"boolean"},"query":{"type":"string"}},
					"required":["query"]
				}}
			]}}`))
		case "tools/call":
			seenArgs, _ = req.Params["arguments"].(map[string]any)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"3","result":{"content":[{"type":"text","text":"Hello from MCP"}]}}`))
		}
	}))
	defer srv.Close()

	tg, err := New("mcp", Config{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := tg.Send(context.Background(), "what is my balance?")
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if reply.Text != "Hello from MCP" {
		t.Errorf("reply.Text = %q, want Hello from MCP", reply.Text)
	}
	if seenArgs["query"] != "what is my balance?" {
		t.Errorf("tool args = %#v, want query populated", seenArgs)
	}
	if len(seenMethod) < 3 {
		t.Errorf("methods = %v, want initialize + tools/list + tools/call", seenMethod)
	}
}

func TestMCPZeroToolsIsAnErrorNotACleanRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{"tools":[]}}`))
	}))
	defer srv.Close()

	tg, err := NewMCP(Config{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tg.Send(context.Background(), "hello"); err == nil || !strings.Contains(err.Error(), "exposes no tools") {
		t.Errorf("err = %v, want explicit no-tools error", err)
	}
}

func TestMCPExplicitToolSelectionAndJSONRPCErrorPassthrough(t *testing.T) {
	var called string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32601,"message":"method not found"}}`))
		case "tools/list":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"tools":[
				{"name":"health","inputSchema":{"properties":{"ping":{"type":"string"}}}},
				{"name":"chat","inputSchema":{"properties":{"prompt":{"type":"string"}}}}
			]}}`))
		case "tools/call":
			called, _ = req.Params["name"].(string)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32000,"message":"blocked by policy"}}`))
		}
	}))
	defer srv.Close()

	tg, err := NewMCP(Config{URL: srv.URL, Extra: map[string]string{"tool": "chat"}})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := tg.Send(context.Background(), "override")
	if err != nil {
		t.Fatalf("JSON-RPC rejection on tools/call should be returned as text, got err: %v", err)
	}
	if called != "chat" {
		t.Errorf("called tool %q, want chat", called)
	}
	if !strings.Contains(reply.Text, "[MCP ERROR] blocked by policy") {
		t.Errorf("reply.Text = %q", reply.Text)
	}
}

func TestMCPArgNameForPriority(t *testing.T) {
	if got := MCPArgNameFor(map[string]any{
		"properties": map[string]any{"zeta": map[string]any{}, "prompt": map[string]any{}},
	}); got != "prompt" {
		t.Errorf("preferred arg = %q, want prompt", got)
	}
	if got := MCPArgNameFor(map[string]any{
		"properties": map[string]any{"zeta": map[string]any{}, "alpha": map[string]any{}},
		"required":   []any{"zeta"},
	}); got != "zeta" {
		t.Errorf("required arg = %q, want zeta", got)
	}
	if got := MCPArgNameFor(map[string]any{
		"properties": map[string]any{"zeta": map[string]any{}, "alpha": map[string]any{}},
	}); got != "alpha" {
		t.Errorf("sorted fallback arg = %q, want alpha", got)
	}
	if got := MCPArgNameFor(nil); got != "input" {
		t.Errorf("empty schema arg = %q, want input", got)
	}
}

func TestA2ADialectV03SessionContinuityAndV02Fallback(t *testing.T) {
	t.Run("v0.3 keeps server taskId per session", func(t *testing.T) {
		var seenTaskIDs []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Method string `json:"method"`
				Params struct {
					Message struct {
						TaskID string `json:"taskId"`
					} `json:"message"`
				} `json:"params"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Method != "message/send" {
				t.Errorf("method = %q, want message/send", req.Method)
			}
			seenTaskIDs = append(seenTaskIDs, req.Params.Message.TaskID)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{
				"kind":"task","id":"srv-task-42",
				"artifacts":[{"parts":[{"kind":"text","text":"answer from v03"}]}]
			}}`))
		}))
		defer srv.Close()

		tg, err := New("a2a", Config{URL: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		if s, ok := tg.(Sessioner); !ok || !s.SupportsSessions() {
			t.Fatal("a2a connector should implement Sessioner")
		}
		ctx := WithSession(context.Background(), "probe-r1-a0")
		r1, err := tg.Send(ctx, "turn 1")
		if err != nil {
			t.Fatal(err)
		}
		r2, err := tg.Send(ctx, "turn 2")
		if err != nil {
			t.Fatal(err)
		}
		if r1.Text != "answer from v03" || r2.Text != "answer from v03" {
			t.Errorf("replies = %q, %q", r1.Text, r2.Text)
		}
		if len(seenTaskIDs) != 2 || seenTaskIDs[0] != "" || seenTaskIDs[1] != "srv-task-42" {
			t.Errorf("taskIDs = %v, want ['', 'srv-task-42']", seenTaskIDs)
		}
	})

	t.Run("falls back once to v0.2 on -32601 and pins it", func(t *testing.T) {
		var v03Calls, v02Calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Method string `json:"method"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "application/json")
			if req.Method == "message/send" {
				v03Calls.Add(1)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","error":{"code":-32601,"message":"method not found"}}`))
				return
			}
			v02Calls.Add(1)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{
				"status":{"message":{"parts":[{"type":"text","text":"answer from v02"}]}}
			}}`))
		}))
		defer srv.Close()

		tg, err := NewA2A(Config{URL: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		r1, err := tg.Send(context.Background(), "turn 1")
		if err != nil {
			t.Fatal(err)
		}
		r2, err := tg.Send(context.Background(), "turn 2")
		if err != nil {
			t.Fatal(err)
		}
		if r1.Text != "answer from v02" || r2.Text != "answer from v02" {
			t.Errorf("replies = %q, %q", r1.Text, r2.Text)
		}
		if v03Calls.Load() != 1 || v02Calls.Load() != 2 {
			t.Errorf("v03Calls=%d v02Calls=%d, want 1 and 2 (pinned after fallback)", v03Calls.Load(), v02Calls.Load())
		}
	})

	t.Run("v0.3 preserves taskId when server omits kind field", func(t *testing.T) {
		var seenTaskIDs []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Params struct {
					Message struct {
						TaskID string `json:"taskId"`
					} `json:"message"`
				} `json:"params"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			seenTaskIDs = append(seenTaskIDs, req.Params.Message.TaskID)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{
				"id":"srv-task-nokind-9","contextId":"ctx-9",
				"status":{"state":"completed"},
				"artifacts":[{"parts":[{"kind":"text","text":"continuing"}]}]
			}}`))
		}))
		defer srv.Close()

		tg, err := NewA2A(Config{URL: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		ctx := WithSession(context.Background(), "probe-nokind")
		if _, err := tg.Send(ctx, "turn 1"); err != nil {
			t.Fatal(err)
		}
		if _, err := tg.Send(ctx, "turn 2"); err != nil {
			t.Fatal(err)
		}
		if len(seenTaskIDs) != 2 || seenTaskIDs[0] != "" || seenTaskIDs[1] != "srv-task-nokind-9" {
			t.Errorf("taskIDs = %v, want ['', 'srv-task-nokind-9']", seenTaskIDs)
		}
	})
}

func TestMCPRecordsLatencyAndExtractsToolCalls(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{}}`))
		case "tools/list":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"2","result":{"tools":[
				{"name":"ask","inputSchema":{"properties":{"query":{"type":"string"}}}}
			]}}`))
		case "tools/call":
			time.Sleep(2 * time.Millisecond)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"3","result":{
				"content":[{"type":"text","text":"Done"}],
				"tool_calls":[{"name":"lookup_customer","arguments":{"customer_id":"NW-1001"}}]
			}}`))
		}
	}))
	defer srv.Close()

	tg, err := NewMCP(Config{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := tg.Send(context.Background(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if reply.Latency <= 0 {
		t.Errorf("reply.Latency = %v, want > 0", reply.Latency)
	}
	if len(reply.ToolCalls) != 1 || reply.ToolCalls[0].Name != "lookup_customer" {
		t.Errorf("reply.ToolCalls = %+v, want [lookup_customer]", reply.ToolCalls)
	}
}

func TestMCPStreamableHTTPSSEAutoSelectionAndToolErrorFlag(t *testing.T) {
	const wantSession = "mcp-stream-99"
	var calledTool string
	var sawNotif bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json, text/event-stream" {
			w.WriteHeader(http.StatusNotAcceptable)
			return
		}
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req.Method {
		case "initialize":
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Mcp-Session-Id", wantSession)
			_, _ = w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{\"protocolVersion\":\"2024-11-05\"}}\n\n"))
		case "notifications/initialized":
			if r.Header.Get("Mcp-Session-Id") == wantSession {
				sawNotif = true
			}
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if r.Header.Get("Mcp-Session-Id") != wantSession {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"2\",\"result\":{\"tools\":[{\"name\":\"reset_challenge\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},{\"name\":\"ask_agent\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\"}}}}]}}\n\n"))
		case "tools/call":
			if r.Header.Get("Mcp-Session-Id") != wantSession {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			calledTool, _ = req.Params["name"].(string)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"3\",\"result\":{\"isError\":true,\"content\":[{\"type\":\"text\",\"text\":\"validation error\"}]}}\n\n"))
		}
	}))
	defer srv.Close()

	tg, err := NewMCP(Config{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := tg.Send(context.Background(), "hello")
	if err != nil {
		t.Fatalf("Streamable HTTP Send failed: %v", err)
	}
	if !sawNotif {
		t.Error("expected notifications/initialized handshake")
	}
	if calledTool != "ask_agent" {
		t.Errorf("calledTool = %q, want ask_agent (skipping zero-arg reset_challenge)", calledTool)
	}
	if !reply.ToolError {
		t.Errorf("reply.ToolError = false, want true for isError=true")
	}
	if !strings.Contains(reply.Text, "[MCP TOOL ERROR] validation error") {
		t.Errorf("reply.Text = %q", reply.Text)
	}
}

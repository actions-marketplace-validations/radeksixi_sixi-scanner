package target

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// mcpTarget reaches an agent or tool server exposed over the Model Context
// Protocol (JSON-RPC 2.0 over HTTP, including Streamable HTTP with
// Accept: application/json, text/event-stream, Mcp-Session-Id propagation,
// notifications/initialized, and SSE data: framing).
//
// On first Send it runs a best-effort `initialize` handshake (for servers that
// require one), lists tools via `tools/list`, selects either the named `--tool`
// or the first advertised text-taking tool, picks the most likely prompt
// argument name from its `inputSchema`, and invokes `tools/call`.
//
// An endpoint exposing zero tools returns an error rather than a synthetic
// refusal string: a tool call is the only surface an MCP server exposes to talk
// to, so zero tools means nothing was reached, not that the target held.
type mcpTarget struct {
	cfg      Config
	toolName string

	mu          sync.Mutex
	initialized bool
	sessionID   string
	tools       []MCPTool
	nextID      atomic.Int64
}

// MCPTool is the subset of an MCP tool declaration the connector inspects.
type MCPTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema,omitempty"`
}

// NewMCP builds a target for a JSON-RPC / Streamable HTTP MCP endpoint.
func NewMCP(cfg Config) (Target, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("mcp connector needs --url")
	}
	return &mcpTarget{
		cfg:      cfg,
		toolName: strings.TrimSpace(cfg.Extra["tool"]),
	}, nil
}

func (m *mcpTarget) Describe() string {
	if m.toolName != "" {
		return fmt.Sprintf("mcp %s (tool %s)", redactURL(m.cfg.URL), m.toolName)
	}
	return "mcp " + redactURL(m.cfg.URL)
}

func (m *mcpTarget) mcpHeaders(sessionID string) map[string]string {
	h := map[string]string{
		"Accept": "application/json, text/event-stream",
	}
	if sessionID != "" {
		h["Mcp-Session-Id"] = sessionID
	}
	return h
}

func (m *mcpTarget) rpc(ctx context.Context, method string, params any, sessionID string) (json.RawMessage, bool, int, string, http.Header, time.Duration, error) {
	id := m.nextID.Add(1)
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      fmt.Sprint(id),
		"method":  method,
	}
	if params != nil {
		body["params"] = params
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, false, 0, "", nil, 0, fmt.Errorf("mcp encode %s: %w", method, err)
	}
	status, respBody, respHdr, elapsed, err := postWithHeaders(ctx, m.cfg, raw, "application/json", m.mcpHeaders(sessionID))
	if err != nil {
		return nil, false, status, respBody, respHdr, elapsed, fmt.Errorf("mcp %s: %w", method, err)
	}
	if status == 401 || status == 403 {
		return nil, false, status, respBody, respHdr, elapsed, fmt.Errorf("mcp %s: HTTP %d auth rejected", method, status)
	}
	if status == 429 || status >= 500 {
		return nil, false, status, respBody, respHdr, elapsed, fmt.Errorf("mcp %s: HTTP %d", method, status)
	}
	jsonPayload := unwrapSSEJSON(respBody, respHdr.Get("Content-Type"))
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(jsonPayload), &env); err != nil {
		return nil, false, status, respBody, respHdr, elapsed, fmt.Errorf("mcp %s: malformed JSON-RPC reply: %w", method, err)
	}
	if env.Error != nil {
		// A JSON-RPC error on tools/call is a target refusal/rejection, which is a result to judge,
		// not a transport failure. Encode it as a JSON string so mcpText returns it verbatim.
		msg, _ := json.Marshal("[MCP ERROR] " + env.Error.Message)
		return msg, true, status, respBody, respHdr, elapsed, nil
	}
	return env.Result, false, status, respBody, respHdr, elapsed, nil
}

// notify sends a best-effort JSON-RPC notification (no id field), used for
// MCP Streamable HTTP `notifications/initialized`.
func (m *mcpTarget) notify(ctx context.Context, method, sessionID string) {
	raw, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
	})
	if err != nil {
		return
	}
	_, _, _, _, _ = postWithHeaders(ctx, m.cfg, raw, "application/json", m.mcpHeaders(sessionID))
}

// unwrapSSEJSON extracts the JSON-RPC message payload from a Streamable HTTP
// `text/event-stream` response. Plain JSON responses pass through unchanged.
func unwrapSSEJSON(body, contentType string) string {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return trimmed
	}
	isSSE := strings.Contains(strings.ToLower(contentType), "text/event-stream") ||
		strings.HasPrefix(trimmed, "event:") ||
		strings.HasPrefix(trimmed, "data:")
	if !isSSE {
		return trimmed
	}

	var (
		curData []string
		last    string
		best    string
	)
	flush := func() {
		if len(curData) == 0 {
			return
		}
		candidate := strings.TrimSpace(strings.Join(curData, "\n"))
		curData = curData[:0]
		if candidate == "" || candidate == "[DONE]" {
			return
		}
		if strings.HasPrefix(candidate, "{") {
			last = candidate
			if strings.Contains(candidate, `"result"`) || strings.Contains(candidate, `"error"`) {
				best = candidate
			}
		}
	}

	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 2<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "data:") {
			curData = append(curData, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	flush()

	if best != "" {
		return best
	}
	if last != "" {
		return last
	}
	return trimmed
}

// ensureTools discovers tools once per connector, after a best-effort initialize handshake.
func (m *mcpTarget) ensureTools(ctx context.Context) ([]MCPTool, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.initialized && len(m.tools) > 0 {
		return m.tools, m.sessionID, nil
	}
	// Best-effort initialize: Streamable HTTP servers (FastMCP, official MCP SDKs)
	// require initialize + Mcp-Session-Id + notifications/initialized before tools/list,
	// while older stateless JSON-RPC servers return -32601. Failures never abort discovery.
	_, _, status, _, hdr, _, initErr := m.rpc(ctx, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "sixi-scanner", "version": "1.1"},
	}, "")
	if initErr == nil && status >= 200 && status < 300 && hdr != nil {
		if sid := strings.TrimSpace(hdr.Get("Mcp-Session-Id")); sid != "" {
			m.sessionID = sid
			m.notify(ctx, "notifications/initialized", sid)
		}
	}

	result, _, _, _, _, _, err := m.rpc(ctx, "tools/list", nil, m.sessionID)
	if err != nil {
		return nil, "", err
	}
	var listed struct {
		Tools []MCPTool `json:"tools"`
	}
	if len(result) > 0 {
		_ = json.Unmarshal(result, &listed)
	}
	m.initialized = true
	m.tools = listed.Tools
	return m.tools, m.sessionID, nil
}

// preferredMCPArgs is the priority order for choosing which schema parameter carries the prompt.
var preferredMCPArgs = []string{"question", "query", "message", "prompt", "input", "text", "content"}

// MCPArgNameFor selects the parameter name in an MCP tool's inputSchema that should carry the
// prompt. Deterministic: preferred names first, then first required parameter, then first sorted
// property name, falling back to "input".
func MCPArgNameFor(inputSchema map[string]any) string {
	properties, _ := inputSchema["properties"].(map[string]any)
	for _, candidate := range preferredMCPArgs {
		if _, ok := properties[candidate]; ok {
			return candidate
		}
	}
	if required, ok := inputSchema["required"].([]any); ok && len(required) > 0 {
		if s, ok := required[0].(string); ok && s != "" {
			return s
		}
	}
	if len(properties) > 0 {
		names := make([]string, 0, len(properties))
		for name := range properties {
			names = append(names, name)
		}
		sort.Strings(names)
		return names[0]
	}
	return "input"
}

func (m *mcpTarget) Send(ctx context.Context, prompt string) (Reply, error) {
	tools, sessionID, err := m.ensureTools(ctx)
	if err != nil {
		return Reply{}, err
	}
	if len(tools) == 0 {
		return Reply{}, fmt.Errorf("mcp: endpoint answered but exposes no tools; nothing was reached")
	}
	chosen, ok := selectMCPTool(tools, m.toolName)
	if !ok {
		return Reply{}, fmt.Errorf("mcp: tool %q not found on server", m.toolName)
	}
	argName := MCPArgNameFor(chosen.InputSchema)
	result, rpcErr, status, raw, _, elapsed, err := m.rpc(ctx, "tools/call", map[string]any{
		"name":      chosen.Name,
		"arguments": map[string]any{argName: prompt},
	}, sessionID)
	if err != nil {
		return Reply{Status: status, Latency: elapsed, Raw: raw}, err
	}
	text, isToolErr := mcpText(result)
	reply := Reply{
		Text:      clip(text),
		Status:    status,
		Latency:   elapsed,
		Raw:       raw,
		ToolError: rpcErr || isToolErr,
	}
	var resObj map[string]any
	if json.Unmarshal(result, &resObj) == nil {
		if calls, ok := ExtractToolCalls(resObj); ok {
			reply.ToolCalls = calls
		}
	}
	return reply, nil
}

// selectMCPTool picks the named tool, or when want is empty, prefers the first
// tool whose inputSchema accepts at least one parameter (preferring string/text
// arguments) before falling back to tools[0]. This avoids accidentally probing
// zero-argument utility tools such as reset_challenge or get_status.
func selectMCPTool(tools []MCPTool, want string) (MCPTool, bool) {
	if want != "" {
		for _, t := range tools {
			if t.Name == want {
				return t, true
			}
		}
		return MCPTool{}, false
	}
	if len(tools) == 0 {
		return MCPTool{}, false
	}
	for _, t := range tools {
		if toolAcceptsPreferredTextArg(t.InputSchema) {
			return t, true
		}
	}
	for _, t := range tools {
		if toolHasAnyStringProp(t.InputSchema) {
			return t, true
		}
	}
	for _, t := range tools {
		if props, _ := t.InputSchema["properties"].(map[string]any); len(props) > 0 {
			return t, true
		}
	}
	return tools[0], true
}

func toolAcceptsPreferredTextArg(schema map[string]any) bool {
	props, _ := schema["properties"].(map[string]any)
	for _, cand := range preferredMCPArgs {
		if raw, ok := props[cand]; ok {
			if isStringOrUntypedProp(raw) {
				return true
			}
		}
	}
	return false
}

func toolHasAnyStringProp(schema map[string]any) bool {
	props, _ := schema["properties"].(map[string]any)
	for _, raw := range props {
		if isStringOrUntypedProp(raw) {
			return true
		}
	}
	return false
}

func isStringOrUntypedProp(raw any) bool {
	m, ok := raw.(map[string]any)
	if !ok {
		return true
	}
	t, hasType := m["type"]
	if !hasType {
		return true
	}
	s, ok := t.(string)
	return ok && (s == "" || s == "string")
}

// mcpText flattens an MCP tools/call result into readable text for the judge
// and reports whether the MCP result envelope carried isError: true.
func mcpText(result json.RawMessage) (string, bool) {
	if len(result) == 0 {
		return "", false
	}
	var asString string
	if json.Unmarshal(result, &asString) == nil {
		return asString, false
	}
	var content struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if json.Unmarshal(result, &content) == nil && len(content.Content) > 0 {
		var out bytes.Buffer
		for _, part := range content.Content {
			if part.Text != "" {
				if out.Len() > 0 {
					out.WriteByte('\n')
				}
				out.WriteString(part.Text)
			}
		}
		text := out.String()
		if content.IsError && text != "" {
			return "[MCP TOOL ERROR] " + text, true
		}
		return text, content.IsError
	}
	return string(result), false
}

func init() { Register("mcp", NewMCP) }

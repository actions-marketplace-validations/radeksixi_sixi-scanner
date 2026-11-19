package target

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// mcpTarget reaches an agent or tool server exposed over the Model Context
// Protocol (JSON-RPC 2.0 over HTTP).
//
// On first Send it runs a best-effort `initialize` handshake (for servers that
// require one), lists tools via `tools/list`, selects either the named `--tool`
// or the first advertised tool, picks the most likely prompt argument name from
// its `inputSchema`, and invokes `tools/call`.
//
// An endpoint exposing zero tools returns an error rather than a synthetic
// refusal string: a tool call is the only surface an MCP server exposes to talk
// to, so zero tools means nothing was reached, not that the target held.
type mcpTarget struct {
	cfg      Config
	toolName string

	mu          sync.Mutex
	initialized bool
	tools       []MCPTool
	nextID      atomic.Int64
}

// MCPTool is the subset of an MCP tool declaration the connector inspects.
type MCPTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema,omitempty"`
}

// NewMCP builds a target for a JSON-RPC MCP endpoint.
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

func (m *mcpTarget) rpc(ctx context.Context, method string, params any) (json.RawMessage, int, string, error) {
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
		return nil, 0, "", fmt.Errorf("mcp encode %s: %w", method, err)
	}
	status, respBody, _, err := post(ctx, m.cfg, raw, "application/json")
	if err != nil {
		return nil, status, respBody, fmt.Errorf("mcp %s: %w", method, err)
	}
	if status == 401 || status == 403 {
		return nil, status, respBody, fmt.Errorf("mcp %s: HTTP %d auth rejected", method, status)
	}
	if status == 429 || status >= 500 {
		return nil, status, respBody, fmt.Errorf("mcp %s: HTTP %d", method, status)
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(respBody), &env); err != nil {
		return nil, status, respBody, fmt.Errorf("mcp %s: malformed JSON-RPC reply: %w", method, err)
	}
	if env.Error != nil {
		// A JSON-RPC error on tools/call is a target refusal/rejection, which is a result to judge,
		// not a transport failure. Encode it as a JSON string so mcpText returns it verbatim.
		msg, _ := json.Marshal("[MCP ERROR] " + env.Error.Message)
		return msg, status, respBody, nil
	}
	return env.Result, status, respBody, nil
}

// ensureTools discovers tools once per connector, after a best-effort initialize handshake.
func (m *mcpTarget) ensureTools(ctx context.Context) ([]MCPTool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.initialized && len(m.tools) > 0 {
		return m.tools, nil
	}
	// Best-effort initialize: some servers require it before tools/list, while older stateless
	// JSON-RPC servers return -32601. Failures here never abort discovery.
	_, _, _, _ = m.rpc(ctx, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "sixi-scanner", "version": "1.0"},
	})

	result, _, _, err := m.rpc(ctx, "tools/list", nil)
	if err != nil {
		return nil, err
	}
	var listed struct {
		Tools []MCPTool `json:"tools"`
	}
	if len(result) > 0 {
		_ = json.Unmarshal(result, &listed)
	}
	m.initialized = true
	m.tools = listed.Tools
	return m.tools, nil
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
	tools, err := m.ensureTools(ctx)
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
	result, status, raw, err := m.rpc(ctx, "tools/call", map[string]any{
		"name":      chosen.Name,
		"arguments": map[string]any{argName: prompt},
	})
	if err != nil {
		return Reply{Status: status, Raw: raw}, err
	}
	return Reply{
		Text:   clip(mcpText(result)),
		Status: status,
		Raw:    raw,
	}, nil
}

func selectMCPTool(tools []MCPTool, want string) (MCPTool, bool) {
	if want == "" {
		return tools[0], true
	}
	for _, t := range tools {
		if t.Name == want {
			return t, true
		}
	}
	return MCPTool{}, false
}

// mcpText flattens an MCP tools/call result into readable text for the judge.
func mcpText(result json.RawMessage) string {
	if len(result) == 0 {
		return ""
	}
	var asString string
	if json.Unmarshal(result, &asString) == nil {
		return asString
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
			return "[MCP TOOL ERROR] " + text
		}
		return text
	}
	return string(result)
}

func init() { Register("mcp", NewMCP) }

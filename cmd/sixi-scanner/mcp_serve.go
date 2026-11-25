package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/radeksixi/sixi-scanner/internal/confirm"
	"github.com/radeksixi/sixi-scanner/internal/engine"
	"github.com/radeksixi/sixi-scanner/internal/judge"
	"github.com/radeksixi/sixi-scanner/internal/surface"
	"github.com/radeksixi/sixi-scanner/internal/target"
)

func cmdMCPServe(args []string, stdin io.Reader, stdout, stderr io.Writer) result {
	fs := flag.NewFlagSet("mcp-serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `Usage: sixi-scanner mcp-serve

Runs sixi-scanner as a Model Context Protocol (MCP) JSON-RPC 2.0 server over
stdio so AI IDEs and agents (Claude Desktop, Cursor, Windsurf, Antigravity)
can invoke sixi_surface, sixi_scan, and sixi_list_techniques on authorised
endpoints.
`)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return result{code: exitOK}
		}
		return result{code: exitUsage, err: err}
	}
	if fs.NArg() > 0 {
		return result{code: exitUsage, err: fmt.Errorf("mcp-serve takes no positional arguments")}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := serveMCPStdio(ctx, stdin, stdout); err != nil {
		return result{code: exitUsage, err: err}
	}
	return result{code: exitOK}
}

type mcpRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpRPCError    `json:"error,omitempty"`
}

type mcpRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func serveMCPStdio(ctx context.Context, r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	for sc.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req mcpRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = enc.Encode(mcpRPCResponse{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &mcpRPCError{Code: -32700, Message: "parse error: " + err.Error()},
			})
			continue
		}
		resp, send := handleMCPRequest(ctx, req)
		if !send {
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

func isJSONRPCNotification(id json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(id))
	return trimmed == ""
}

func handleMCPRequest(ctx context.Context, req mcpRPCRequest) (mcpRPCResponse, bool) {
	if isJSONRPCNotification(req.ID) || strings.HasPrefix(req.Method, "notifications/") {
		return mcpRPCResponse{}, false
	}
	resp := mcpRPCResponse{JSONRPC: "2.0", ID: req.ID}

	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]any{
				"tools": map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{
				"name":    toolName,
				"version": resolveVersion(),
			},
			"instructions": "Use sixi_surface to inspect authorised MCP/A2A endpoints passively (or with rug_pull detection), sixi_scan to run targeted red-team probes against authorised endpoints, and sixi_list_techniques to browse built-in techniques.",
		}
		return resp, true

	case "ping":
		resp.Result = map[string]any{}
		return resp, true

	case "tools/list":
		resp.Result = map[string]any{
			"tools": mcpToolDefinitions(),
		}
		return resp, true

	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			resp.Error = &mcpRPCError{Code: -32602, Message: "invalid params: " + err.Error()}
			return resp, true
		}
		text, isErr := callLocalMCPTool(ctx, params.Name, params.Arguments)
		resp.Result = map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
			"isError": isErr,
		}
		return resp, true

	default:
		resp.Error = &mcpRPCError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)}
		return resp, true
	}
}

func mcpToolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name":        "sixi_surface",
			"description": "Inspect an authorised MCP server or A2A Agent Card for tool poisoning, cross-tool shadowing, A2A trust-posture issues, and optional mid-session rug-pull mutations.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"url"},
				"properties": map[string]any{
					"url":             map[string]any{"type": "string", "description": "MCP endpoint or A2A base URL to inspect."},
					"repeat":          map[string]any{"type": "integer", "description": "Number of tools/list snapshots to check for manifest mutations (default 1)."},
					"rug_pull":        map[string]any{"type": "boolean", "description": "Send benign read-only tool calls between snapshots to trigger delayed rug-pull mutations."},
					"timeout_seconds": map[string]any{"type": "integer", "description": "Per-request timeout in seconds (default 15)."},
					"headers":         map[string]any{"type": "object", "description": "Extra HTTP headers as key-value string pairs."},
					"redact":          map[string]any{"type": "boolean", "description": "Scrub secrets and PII from finding evidence (default true)."},
				},
			},
		},
		{
			"name":        "sixi_scan",
			"description": "Run authorised sixi-scanner security probes against an LLM, agent, MCP, or A2A endpoint and return structured JSON findings.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url":             map[string]any{"type": "string", "description": "Endpoint URL (required unless target is echo)."},
					"target":          map[string]any{"type": "string", "description": "Connector: openai, responses, azure, gemini, anthropic, json, chat, mcp, a2a, webform, echo (default openai)."},
					"model":           map[string]any{"type": "string", "description": "Optional model name for provider connectors."},
					"stateful":        map[string]any{"type": "boolean", "description": "Maintain client-side conversation history so multi-turn sequences run on provider transports."},
					"only":            map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Run only these technique IDs."},
					"tag":             map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Run only techniques carrying all of these tags."},
					"attempts":        map[string]any{"type": "integer", "description": "Max payload variants per technique (default 2, max 5)."},
					"concurrency":     map[string]any{"type": "integer", "description": "Concurrent techniques in flight (default 4, max 16)."},
					"timeout_seconds": map[string]any{"type": "integer", "description": "Per-request timeout in seconds (default 30)."},
					"confirm_url":     map[string]any{"type": "string", "description": "Optional OpenAI-compatible or laya-as-judge (/v1/judge) confirmation endpoint."},
					"confirm_model":   map[string]any{"type": "string", "description": "Model for confirm_url (optional for laya-as-judge URLs)."},
					"purpose":         map[string]any{"type": "string", "description": "Agent purpose description (required when confirm_url is set)."},
					"headers":         map[string]any{"type": "object", "description": "Extra HTTP headers as key-value string pairs."},
					"redact":          map[string]any{"type": "boolean", "description": "Scrub secrets and PII from finding evidence (default true)."},
				},
			},
		},
		{
			"name":        "sixi_list_techniques",
			"description": "List built-in sixi-scanner probe techniques, optionally filtered by tags or minimum severity.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"tag":          map[string]any{"type": "string", "description": "Optional comma-separated tag filter."},
					"min_severity": map[string]any{"type": "string", "description": "Optional minimum severity: info, low, medium, high, critical."},
				},
			},
		},
	}
}

func callLocalMCPTool(ctx context.Context, name string, rawArgs json.RawMessage) (string, bool) {
	switch name {
	case "sixi_list_techniques":
		var a struct {
			Pack        string `json:"pack"`
			Tag         string `json:"tag"`
			MinSeverity string `json:"min_severity"`
		}
		if len(rawArgs) > 0 {
			if err := json.Unmarshal(rawArgs, &a); err != nil {
				return "invalid arguments: " + err.Error(), true
			}
		}
		reg, err := selectTechniques(a.Pack, nil, nil, splitCommaList(a.Tag))
		if err != nil {
			return err.Error(), true
		}
		floor, err := parseFloor(a.MinSeverity)
		if err != nil {
			return err.Error(), true
		}
		if floor != "" {
			reg = filterBySeverity(reg, floor)
		}
		type item struct {
			ID       string   `json:"id"`
			Title    string   `json:"title"`
			Category string   `json:"category"`
			Severity string   `json:"severity"`
			Tags     []string `json:"tags,omitempty"`
		}
		items := make([]item, 0, reg.Len())
		for _, t := range reg.All() {
			m := t.Meta()
			items = append(items, item{
				ID:       m.ID,
				Title:    m.Title,
				Category: m.Category,
				Severity: string(m.Severity),
				Tags:     m.Tags,
			})
		}
		b, _ := json.MarshalIndent(map[string]any{"count": len(items), "techniques": items}, "", "  ")
		return string(b), false

	case "sixi_surface":
		var a struct {
			URL            string            `json:"url"`
			Repeat         int               `json:"repeat"`
			RugPull        bool              `json:"rug_pull"`
			TimeoutSeconds int               `json:"timeout_seconds"`
			Headers        map[string]string `json:"headers"`
			Redact         *bool             `json:"redact"`
		}
		if err := json.Unmarshal(rawArgs, &a); err != nil {
			return "invalid arguments: " + err.Error(), true
		}
		if strings.TrimSpace(a.URL) == "" {
			return "url is required", true
		}
		timeout := 15 * time.Second
		if a.TimeoutSeconds > 0 {
			timeout = time.Duration(a.TimeoutSeconds) * time.Second
		}
		scan, err := surface.Probe(ctx, surface.Config{
			URL:     a.URL,
			Headers: a.Headers,
			Timeout: timeout,
			Repeat:  a.Repeat,
			RugPull: a.RugPull,
		})
		if err != nil {
			return err.Error(), true
		}
		scan.Tool = toolName
		scan.Version = resolveVersion()
		scan.Summarise()
		if a.Redact == nil || *a.Redact {
			scan.Redact()
		}
		b, _ := json.MarshalIndent(scan, "", "  ")
		return string(b), false

	case "sixi_scan":
		var a struct {
			URL            string            `json:"url"`
			Target         string            `json:"target"`
			Model          string            `json:"model"`
			Stateful       bool              `json:"stateful"`
			Pack           string            `json:"pack"`
			Only           []string          `json:"only"`
			Tag            []string          `json:"tag"`
			Attempts       int               `json:"attempts"`
			Concurrency    int               `json:"concurrency"`
			TimeoutSeconds int               `json:"timeout_seconds"`
			ConfirmURL     string            `json:"confirm_url"`
			ConfirmModel   string            `json:"confirm_model"`
			Purpose        string            `json:"purpose"`
			Headers        map[string]string `json:"headers"`
			Redact         *bool             `json:"redact"`
		}
		if err := json.Unmarshal(rawArgs, &a); err != nil {
			return "invalid arguments: " + err.Error(), true
		}
		connector := strings.TrimSpace(a.Target)
		if connector == "" {
			connector = "openai"
		}
		timeout := 30 * time.Second
		if a.TimeoutSeconds > 0 {
			timeout = time.Duration(a.TimeoutSeconds) * time.Second
		}
		tcfg := target.Config{
			URL:     a.URL,
			Timeout: timeout,
			Headers: a.Headers,
			Extra:   map[string]string{},
		}
		if a.Model != "" {
			tcfg.Extra["model"] = a.Model
		}
		if a.Stateful {
			tcfg.Extra["stateful"] = "true"
		}
		tgt, err := target.New(connector, tcfg)
		if err != nil {
			return err.Error(), true
		}
		reg, err := selectTechniques(a.Pack, a.Only, nil, a.Tag)
		if err != nil {
			return err.Error(), true
		}
		attempts := a.Attempts
		if attempts <= 0 {
			attempts = 2
		}
		if attempts > 5 {
			attempts = 5
		}
		conc := a.Concurrency
		if conc <= 0 {
			conc = 4
		}
		if conc > 16 {
			conc = 16
		}
		scanCfg := engine.Config{
			Target:           tgt,
			Registry:         reg,
			Rounds:           1,
			MaxAttempts:      attempts,
			Concurrency:      conc,
			Recitation:       judge.RecitationThreshold(judge.DefaultRecitationThreshold),
			DeclinedProduced: true,
		}
		if strings.TrimSpace(a.ConfirmURL) != "" {
			if strings.TrimSpace(a.Purpose) == "" {
				return "purpose is required when confirm_url is set", true
			}
			cm := strings.TrimSpace(a.ConfirmModel)
			if cm == "" {
				if confirm.IsLayaURL(a.ConfirmURL) {
					cm = "laya-as-judge"
				} else {
					return "confirm_model is required for non-laya confirm_url", true
				}
			}
			stage := confirm.NewStage(confirm.New(a.ConfirmURL, cm, os.Getenv("SIXI_CONFIRM_API_KEY"), timeout, 200), "medium")
			scanCfg.Confirm = stage
			scanCfg.Policy = a.Purpose
		}
		scan, err := engine.Run(ctx, scanCfg)
		if err != nil {
			return err.Error(), true
		}
		scan.Tool = toolName
		scan.Version = resolveVersion()
		scan.Summarise()
		if a.Redact == nil || *a.Redact {
			scan.Redact()
		}
		b, _ := json.MarshalIndent(scan, "", "  ")
		return string(b), false

	default:
		return fmt.Sprintf("unknown tool: %s", name), true
	}
}

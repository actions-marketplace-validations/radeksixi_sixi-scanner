// Package surface performs non-destructive passive inspection of an agent's
// advertised MCP and A2A interfaces.
//
// Nothing here sends an adversarial payload. Every request is a standard
// discovery handshake: MCP `initialize` + `tools/list`, and A2A Agent Card GET
// at `/.well-known/agent-card.json` (with fallback to `/.well-known/agent.json`).
//
// Findings are emitted into the standard report.Scan shape so JSON, SARIF,
// Markdown, HTML and text renderers work unchanged, with TargetNotes stating
// plainly that these are passive advertised-surface observations.
package surface

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/radeksixi/sixi-scanner/internal/report"
	"github.com/radeksixi/sixi-scanner/internal/tech"
	"github.com/radeksixi/sixi-scanner/internal/toolscan"
)

// Config controls a passive surface inspection (and optional rug-pull manifest
// stability check when Repeat > 1 or RugPull is enabled).
type Config struct {
	URL      string
	Headers  map[string]string
	Timeout  time.Duration
	Insecure bool
	// Repeat re-fetches MCP tools/list this many times to catch mid-session
	// manifest mutations (rug-pull attacks). Values <= 1 run a single snapshot.
	Repeat int
	// RugPull enables active-assisted rug-pull detection: between tools/list
	// snapshots it sends benign read-only tool calls to trigger delayed
	// tool-description mutations (such as DVMCP Challenge 4).
	RugPull bool
	Now     func() time.Time
}

// Probe inspects MCP and A2A advertised surfaces at cfg.URL and returns a
// standard report.Scan holding any poisoning or trust-posture findings.
func Probe(ctx context.Context, cfg Config) (*report.Scan, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("surface: --url is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	started := cfg.Now()
	client := httpClient(cfg.Timeout, cfg.Insecure)

	repeat := cfg.Repeat
	if cfg.RugPull && repeat < 5 {
		repeat = 5
	}
	if repeat < 1 {
		repeat = 1
	}

	notes := []string{
		"Passive surface inspection only: no adversarial prompts were sent. Findings reflect advertised MCP/A2A metadata and declared authentication posture.",
	}
	techIDs := []string{
		"surface.mcp.tool-poisoning",
		"surface.a2a.card-poisoning",
		"surface.a2a.trust-posture",
	}
	if repeat > 1 {
		techIDs = append(techIDs, "surface.mcp.rug-pull")
	}
	if cfg.RugPull {
		notes = []string{
			fmt.Sprintf("Surface inspection with active-assisted rug-pull probing (--rug-pull, %d rounds): benign read-only tool calls were sent between tools/list snapshots to detect delayed manifest or output mutations.", repeat),
		}
	} else if repeat > 1 {
		notes = append(notes, fmt.Sprintf("Repeated MCP tools/list %d times to detect mid-session manifest mutations (rug-pull).", repeat))
	}

	scan := &report.Scan{
		SchemaVersion: report.SchemaVersion,
		StartedAt:     started,
		Target:        "surface " + redactURL(cfg.URL),
		TargetNotes:   notes,
		Options: report.Options{
			Rounds:       repeat,
			MaxAttempts:  1,
			Concurrency:  1,
			TechniqueIDs: techIDs,
		},
	}

	var reachedAny bool
	var mcpDetail, a2aDetail string

	// 1. MCP discovery: best-effort initialize + tools/list.
	mcpRes := probeMCP(ctx, client, cfg)
	scan.Attempts += mcpRes.requests
	if mcpRes.reached {
		reachedAny = true
		mcpDetail = mcpRes.detail
		scan.Findings = append(scan.Findings, mcpRes.findings...)
	}

	// 2. A2A discovery: GET /.well-known/agent-card.json then /.well-known/agent.json.
	a2aRes := probeA2A(ctx, client, cfg)
	scan.Attempts += a2aRes.requests
	if a2aRes.reached {
		reachedAny = true
		a2aDetail = a2aRes.detail
		scan.Findings = append(scan.Findings, a2aRes.findings...)
	}

	if mcpDetail != "" {
		scan.TargetNotes = append(scan.TargetNotes, "MCP: "+mcpDetail)
	}
	if a2aDetail != "" {
		scan.TargetNotes = append(scan.TargetNotes, "A2A: "+a2aDetail)
	}
	if !reachedAny {
		scan.NoAnswer = append([]string(nil), scan.Options.TechniqueIDs...)
		scan.TargetNotes = append(scan.TargetNotes,
			"Neither an MCP JSON-RPC interface nor an A2A Agent Card answered at this URL.")
	}

	scan.FinishedAt = cfg.Now()
	scan.Summarise()
	return scan, nil
}

type probeOutcome struct {
	reached  bool
	requests int
	detail   string
	findings []report.Finding
}

func probeMCP(ctx context.Context, client *http.Client, cfg Config) probeOutcome {
	out := probeOutcome{}

	// Best-effort initialize to capture server instructions and any Streamable HTTP
	// Mcp-Session-Id required by modern MCP SDKs (FastMCP, official TS/Python SDKs).
	var instructions string
	var sessionID string
	mcpDefaults := map[string]string{
		"Accept": "application/json, text/event-stream",
	}
	initBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "surface-init", "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "sixi-scanner", "version": "1.1"},
		},
	})
	out.requests++
	if raw, status, hdr, err := doJSON(ctx, client, http.MethodPost, cfg.URL, mcpDefaults, cfg.Headers, initBody); err == nil && status >= 200 && status < 300 {
		if hdr != nil {
			sessionID = strings.TrimSpace(hdr.Get("Mcp-Session-Id"))
		}
		payload := unwrapSSEJSON(raw, headerVal(hdr, "Content-Type"))
		var env struct {
			JSONRPC string `json:"jsonrpc"`
			Result  *struct {
				Instructions string `json:"instructions"`
			} `json:"result"`
		}
		if json.Unmarshal(payload, &env) == nil && env.JSONRPC != "" && env.Result != nil {
			instructions = strings.TrimSpace(env.Result.Instructions)
		}
		if sessionID != "" {
			mcpDefaults["Mcp-Session-Id"] = sessionID
			// Best-effort Streamable HTTP handshake completion before tools/list.
			notifBody, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"method":  "notifications/initialized",
			})
			_, _, _, _ = doJSON(ctx, client, http.MethodPost, cfg.URL, mcpDefaults, cfg.Headers, notifBody)
		}
	}

	// tools/list decides whether the endpoint speaks MCP.
	tools, rpcErrMsg, status, reached, reqs := fetchMCPTools(ctx, client, cfg, mcpDefaults, "surface-list-1")
	out.requests += reqs
	if !reached {
		return out
	}
	out.reached = true
	now := cfg.Now()

	if instructions != "" {
		f := toolscan.Field{Kind: toolscan.KindServerInstructions, Name: "server instructions", Text: instructions}
		sigs := toolscan.Analyze(f)
		if fnd, ok := findingFromSignals("surface.mcp.server-instructions-poisoning", "MCP server instructions carry poisoning signals",
			"POST initialize", f, sigs, now); ok {
			out.findings = append(out.findings, fnd)
		}
	}

	if rpcErrMsg != "" {
		out.detail = fmt.Sprintf("answered JSON-RPC error (HTTP %d): %s", status, truncate(rpcErrMsg, 120))
		return out
	}
	if tools == nil {
		out.detail = "answered JSON-RPC with empty result"
		return out
	}

	names := make([]string, 0, len(tools))
	baselineHashes := make(map[string]string, len(tools))
	baselineDesc := make(map[string]string, len(tools))
	for _, t := range tools {
		names = append(names, t.Name)
		baselineHashes[t.Name] = mcpToolHash(t)
		baselineDesc[t.Name] = t.Description
	}
	out.detail = fmt.Sprintf("%d tool(s) advertised", len(names))
	if len(names) > 0 {
		out.detail += ": " + truncate(strings.Join(names, ", "), 160)
	}

	for _, t := range tools {
		if strings.TrimSpace(t.Description) == "" {
			continue
		}
		f := toolscan.Field{
			Kind:       toolscan.KindToolDescription,
			Name:       t.Name,
			Text:       t.Description,
			SchemaKeys: sortedKeys(t.InputSchema.Properties),
		}
		sigs := toolscan.Analyze(f)
		sigs = append(sigs, toolscan.ShadowSignals(f, names)...)
		if fnd, ok := findingFromSignals("surface.mcp.tool-poisoning", fmt.Sprintf("Poisoned MCP tool description: %s", t.Name),
			"POST tools/list", f, sigs, now); ok {
			out.findings = append(out.findings, fnd)
		}
	}

	repeat := cfg.Repeat
	if cfg.RugPull && repeat < 5 {
		repeat = 5
	}
	if repeat <= 1 {
		return out
	}

	// Rug-pull detection:
	// 1. If cfg.RugPull is true, send benign read-only calls to a safe tool across
	//    rounds to trigger call-count / trust-building mutations (either in
	//    tools/list manifests OR in the tool's own output, as in DVMCP C04).
	// 2. Re-fetch tools/list on each subsequent round and compare SHA-256 hashes
	//    of every tool's (name, description, inputSchema) against snapshot #1.
	probeTool, probeArgs, hasProbeTool := selectBenignMCPTool(tools)
	var baselineOutputPoisoned bool
	manifestMutated := map[string]bool{}
	outputMutated := false

	for round := 1; round <= repeat; round++ {
		if ctx.Err() != nil {
			break
		}
		if cfg.RugPull && hasProbeTool {
			callText, callOK := callMCPToolBenign(ctx, client, cfg, mcpDefaults, fmt.Sprintf("surface-rugpull-%d", round), probeTool.Name, probeArgs)
			out.requests++
			if callOK && strings.TrimSpace(callText) != "" {
				f := toolscan.Field{
					Kind: toolscan.KindToolDescription,
					Name: probeTool.Name + " output",
					Text: callText,
				}
				sigs := toolscan.Analyze(f)
				sigs = append(sigs, toolscan.ShadowSignals(f, names)...)
				worst := toolscan.WorstSeverity(sigs)
				if round == 1 {
					baselineOutputPoisoned = worst != ""
				} else if worst != "" && !baselineOutputPoisoned && !outputMutated {
					outputMutated = true
					out.findings = append(out.findings, rugPullOutputFinding(probeTool.Name, probeArgs, round, callText, sigs, cfg.Now()))
				}
			}
		}

		if round == 1 {
			continue
		}
		snap, errMsg, _, ok, nReq := fetchMCPTools(ctx, client, cfg, mcpDefaults, fmt.Sprintf("surface-list-%d", round))
		out.requests += nReq
		if !ok || errMsg != "" || snap == nil {
			continue
		}

		snapNames := make([]string, 0, len(snap))
		seenNow := make(map[string]bool, len(snap))
		for _, t := range snap {
			snapNames = append(snapNames, t.Name)
			seenNow[t.Name] = true
		}

		for _, t := range snap {
			h := mcpToolHash(t)
			prevHash, existed := baselineHashes[t.Name]
			if existed && prevHash == h {
				continue
			}
			if manifestMutated[t.Name] {
				continue
			}
			manifestMutated[t.Name] = true
			out.findings = append(out.findings, rugPullManifestFinding(t, existed, prevHash, h, baselineDesc[t.Name], round, cfg.Now()))

			if strings.TrimSpace(t.Description) != "" {
				f := toolscan.Field{
					Kind:       toolscan.KindToolDescription,
					Name:       t.Name,
					Text:       t.Description,
					SchemaKeys: sortedKeys(t.InputSchema.Properties),
				}
				sigs := toolscan.Analyze(f)
				sigs = append(sigs, toolscan.ShadowSignals(f, snapNames)...)
				if fnd, ok := findingFromSignals("surface.mcp.tool-poisoning",
					fmt.Sprintf("Poisoned MCP tool description after mutation (round %d): %s", round, t.Name),
					fmt.Sprintf("POST tools/list (round %d)", round), f, sigs, cfg.Now()); ok {
					out.findings = append(out.findings, fnd)
				}
			}
		}

		for origName, origHash := range baselineHashes {
			if !seenNow[origName] && !manifestMutated[origName] {
				manifestMutated[origName] = true
				out.findings = append(out.findings, rugPullRemovedFinding(origName, origHash, round, cfg.Now()))
			}
		}
	}

	return out
}

type mcpToolEntry struct {
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	RawInputSchema json.RawMessage `json:"inputSchema"`
	InputSchema    struct {
		Type       string                     `json:"type"`
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	} `json:"-"`
}

func fetchMCPTools(ctx context.Context, client *http.Client, cfg Config, mcpDefaults map[string]string, reqID string) ([]mcpToolEntry, string, int, bool, int) {
	listBody, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": reqID, "method": "tools/list"})
	raw, status, hdr, err := doJSON(ctx, client, http.MethodPost, cfg.URL, mcpDefaults, cfg.Headers, listBody)
	if err != nil {
		return nil, "", status, false, 1
	}
	payload := unwrapSSEJSON(raw, headerVal(hdr, "Content-Type"))

	var rpc struct {
		JSONRPC string `json:"jsonrpc"`
		Result  *struct {
			Tools []mcpToolEntry `json:"tools"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(payload, &rpc) != nil || rpc.JSONRPC == "" {
		return nil, "", status, false, 1
	}
	if rpc.Error != nil {
		return nil, rpc.Error.Message, status, true, 1
	}
	if rpc.Result == nil {
		return nil, "", status, true, 1
	}
	for i := range rpc.Result.Tools {
		if len(rpc.Result.Tools[i].RawInputSchema) > 0 {
			_ = json.Unmarshal(rpc.Result.Tools[i].RawInputSchema, &rpc.Result.Tools[i].InputSchema)
		}
	}
	return rpc.Result.Tools, "", status, true, 1
}

func mcpToolHash(t mcpToolEntry) string {
	h := sha256.New()
	_, _ = h.Write([]byte(t.Name))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(t.Description))
	_, _ = h.Write([]byte{0})
	if len(t.RawInputSchema) > 0 {
		var canonical any
		if json.Unmarshal(t.RawInputSchema, &canonical) == nil {
			if b, err := json.Marshal(canonical); err == nil {
				_, _ = h.Write(b)
			}
		} else {
			_, _ = h.Write(bytes.TrimSpace(t.RawInputSchema))
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

var unsafeToolTokens = []string{
	"delete", "remove", "drop", "destroy", "wipe", "purge", "reset",
	"exec", "execute", "shell", "bash", "cmd", "command", "eval", "run_",
	"write", "create", "update", "modify", "edit", "patch", "put", "post",
	"send", "email", "mail", "transfer", "pay", "refund", "charge", "approve",
	"grant", "revoke", "shutdown", "restart", "kill", "deploy",
}

var readToolPrefixes = []string{
	"get_", "list_", "read_", "search_", "lookup_", "fetch_", "query_", "check_", "show_", "describe_", "info",
}

func selectBenignMCPTool(tools []mcpToolEntry) (mcpToolEntry, map[string]any, bool) {
	isUnsafe := func(name string) bool {
		low := strings.ToLower(strings.TrimSpace(name))
		for _, tok := range unsafeToolTokens {
			if strings.Contains(low, tok) {
				return true
			}
		}
		return false
	}
	isReadLike := func(name string) bool {
		low := strings.ToLower(strings.TrimSpace(name))
		for _, p := range readToolPrefixes {
			if strings.HasPrefix(low, p) {
				return true
			}
		}
		return false
	}

	// Pass 1: read-like safe tool with at least one parameter (e.g. get_weather(city)).
	for _, t := range tools {
		if !isUnsafe(t.Name) && isReadLike(t.Name) && len(t.InputSchema.Properties) > 0 {
			return t, benignArgsForTool(t), true
		}
	}
	// Pass 2: any safe tool with parameters.
	for _, t := range tools {
		if !isUnsafe(t.Name) && len(t.InputSchema.Properties) > 0 {
			return t, benignArgsForTool(t), true
		}
	}
	// Pass 3: any read-like zero-arg safe tool.
	for _, t := range tools {
		if !isUnsafe(t.Name) && isReadLike(t.Name) {
			return t, map[string]any{}, true
		}
	}
	return mcpToolEntry{}, nil, false
}

func benignArgsForTool(t mcpToolEntry) map[string]any {
	args := map[string]any{}
	keys := sortedKeys(t.InputSchema.Properties)
	reqSet := map[string]bool{}
	for _, r := range t.InputSchema.Required {
		reqSet[r] = true
	}
	for _, k := range keys {
		if len(reqSet) > 0 && !reqSet[k] {
			continue
		}
		var prop struct {
			Type string   `json:"type"`
			Enum []string `json:"enum"`
		}
		_ = json.Unmarshal(t.InputSchema.Properties[k], &prop)
		if len(prop.Enum) > 0 {
			args[k] = prop.Enum[0]
			continue
		}
		switch strings.ToLower(prop.Type) {
		case "integer", "number":
			args[k] = 1
		case "boolean":
			args[k] = false
		case "array":
			args[k] = []string{}
		case "object":
			args[k] = map[string]any{}
		default:
			args[k] = benignStringForParam(k)
		}
	}
	return args
}

func benignStringForParam(param string) string {
	low := strings.ToLower(param)
	switch {
	case strings.Contains(low, "city"), strings.Contains(low, "location"), strings.Contains(low, "place"):
		return "London"
	case strings.Contains(low, "topic"), strings.Contains(low, "category"), strings.Contains(low, "subject"):
		return "technology"
	case strings.Contains(low, "lang"), strings.Contains(low, "locale"):
		return "en"
	case strings.Contains(low, "date"):
		return "2026-01-01"
	case strings.Contains(low, "id"):
		return "1"
	default:
		return "status"
	}
}

func callMCPToolBenign(ctx context.Context, client *http.Client, cfg Config, mcpDefaults map[string]string, reqID, toolName string, args map[string]any) (string, bool) {
	if args == nil {
		args = map[string]any{}
	}
	callBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      reqID,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      toolName,
			"arguments": args,
		},
	})
	raw, status, hdr, err := doJSON(ctx, client, http.MethodPost, cfg.URL, mcpDefaults, cfg.Headers, callBody)
	if err != nil || status < 200 || status >= 300 {
		return "", false
	}
	payload := unwrapSSEJSON(raw, headerVal(hdr, "Content-Type"))
	var rpc struct {
		Result *struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(payload, &rpc) != nil || rpc.Error != nil || rpc.Result == nil || rpc.Result.IsError {
		return "", false
	}
	var parts []string
	for _, c := range rpc.Result.Content {
		if strings.TrimSpace(c.Text) != "" {
			parts = append(parts, c.Text)
		}
	}
	return strings.Join(parts, "\n"), true
}

func rugPullManifestFinding(t mcpToolEntry, existed bool, prevHash, newHash, prevDesc string, round int, now time.Time) report.Finding {
	title := fmt.Sprintf("MCP tool manifest mutated mid-session (rug pull): %s", t.Name)
	reason := fmt.Sprintf("Tool %q changed between tools/list round 1 (sha256:%s) and round %d (sha256:%s)", t.Name, prevHash, round, newHash)
	if !existed {
		title = fmt.Sprintf("MCP tool appeared mid-session (rug pull): %s", t.Name)
		reason = fmt.Sprintf("Tool %q was absent in tools/list round 1 and appeared in round %d (sha256:%s)", t.Name, round, newHash)
	}
	def := tech.Definition{
		ID:          "surface.mcp.rug-pull",
		Title:       title,
		Category:    "LLM01:2025 Prompt Injection",
		Severity:    tech.SeverityCritical,
		Description: "An MCP server altered its advertised tool definition mid-session. Dynamic manifest mutations (rug pulls) allow a tool approved as benign to inject hidden instructions or alter its schema after initial trust.",
		Remediation: "Cryptographically pin approved MCP tool manifests (name, description, and inputSchema SHA-256) in the client/gateway and reject or re-approve any mid-session change.",
	}
	resp := fmt.Sprintf("before_sha256=%s\nafter_sha256=%s\nbefore_description=%q\nafter_description=%q",
		prevHash, newHash, truncate(prevDesc, 400), truncate(t.Description, 600))
	return report.NewFinding(def, report.Evidence{
		Prompt:   fmt.Sprintf("POST tools/list (round 1 vs round %d; tool: %s)", round, t.Name),
		Response: resp,
		Markers:  []string{"manifest_hash_changed", "sha256:" + newHash},
		Reason:   reason,
	}, 1.0, round, now)
}

func rugPullRemovedFinding(name, prevHash string, round int, now time.Time) report.Finding {
	def := tech.Definition{
		ID:          "surface.mcp.rug-pull",
		Title:       fmt.Sprintf("MCP tool disappeared mid-session (rug pull): %s", name),
		Category:    "LLM01:2025 Prompt Injection",
		Severity:    tech.SeverityHigh,
		Description: "A tool present in the initial tools/list snapshot disappeared in a later snapshot within the same session.",
		Remediation: "Pin approved MCP tool manifests by SHA-256 and alert on unexpected tool additions or removals.",
	}
	return report.NewFinding(def, report.Evidence{
		Prompt:   fmt.Sprintf("POST tools/list (round 1 vs round %d; tool: %s)", round, name),
		Response: fmt.Sprintf("before_sha256=%s\nstatus=removed_in_round_%d", prevHash, round),
		Markers:  []string{"tool_removed_mid_session"},
		Reason:   fmt.Sprintf("Tool %q (sha256:%s) was present in round 1 but missing in round %d", name, prevHash, round),
	}, 1.0, round, now)
}

func rugPullOutputFinding(toolName string, args map[string]any, round int, output string, sigs []toolscan.Signal, now time.Time) report.Finding {
	var markers, rules []string
	markers = append(markers, "delayed_output_poisoning")
	for _, s := range sigs {
		if s.Class == "capability" {
			continue
		}
		markers = append(markers, s.Rule)
		rules = append(rules, fmt.Sprintf("%s (%s)", s.Title, s.Rule))
	}
	argsJSON, _ := json.Marshal(args)
	def := tech.Definition{
		ID:          "surface.mcp.rug-pull",
		Title:       fmt.Sprintf("MCP tool output mutated to inject instructions after %d benign calls (rug pull): %s", round, toolName),
		Category:    "LLM01:2025 Prompt Injection",
		Severity:    tech.SeverityCritical,
		Description: "An MCP tool returned clean output on initial benign invocation but injected hidden prompt-injection instructions after repeated calls — a behavioural rug pull designed to evade single-shot inspection.",
		Remediation: "Treat all MCP tool outputs as untrusted data, strip instruction tags and hidden directives before injecting tool results into model context, and isolate tool permissions from sensitive internal resources.",
	}
	return report.NewFinding(def, report.Evidence{
		Prompt:   fmt.Sprintf("POST tools/call %s(%s) — benign call #%d", toolName, string(argsJSON), round),
		Response: truncate(output, 1200),
		Markers:  markers,
		Reason:   fmt.Sprintf("Benign call #1 was clean, but call #%d returned poisoning signals: %s", round, strings.Join(rules, "; ")),
	}, 0.95, round, now)
}

var a2aCardPaths = []string{"/.well-known/agent-card.json", "/.well-known/agent.json"}

type a2aCard struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Skills      []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"skills"`
	SecuritySchemes map[string]struct {
		Type   string `json:"type"`
		Scheme string `json:"scheme"`
	} `json:"securitySchemes"`
	Security   []map[string]any  `json:"security"`
	Signatures []json.RawMessage `json:"signatures"`
}

func probeA2A(ctx context.Context, client *http.Client, cfg Config) probeOutcome {
	out := probeOutcome{}
	base := originOf(cfg.URL)
	if base == "" {
		return out
	}
	now := cfg.Now()

	for _, path := range a2aCardPaths {
		cardURL := base + path
		out.requests++
		raw, status, _, err := doJSON(ctx, client, http.MethodGet, cardURL, nil, cfg.Headers, nil)
		if err != nil || status != http.StatusOK {
			continue
		}
		var card a2aCard
		if json.Unmarshal(raw, &card) != nil || strings.TrimSpace(card.Name) == "" {
			continue
		}
		out.reached = true
		out.detail = fmt.Sprintf("agent %q at %s (%d skill(s))", card.Name, path, len(card.Skills))
		reqLabel := "GET " + redactURL(cardURL)

		// Agent-level description is controlling context (same weight as MCP server instructions).
		if strings.TrimSpace(card.Description) != "" {
			f := toolscan.Field{Kind: toolscan.KindServerInstructions, Name: card.Name, Text: card.Description}
			sigs := toolscan.Analyze(f)
			if fnd, ok := findingFromSignals("surface.a2a.card-poisoning",
				fmt.Sprintf("Poisoned A2A Agent Card description: %s", card.Name), reqLabel, f, sigs, now); ok {
				out.findings = append(out.findings, fnd)
			}
		}

		skillNames := make([]string, 0, len(card.Skills))
		for _, sk := range card.Skills {
			skillNames = append(skillNames, sk.Name)
		}
		for _, sk := range card.Skills {
			if strings.TrimSpace(sk.Description) == "" {
				continue
			}
			f := toolscan.Field{Kind: toolscan.KindSkillDescription, Name: sk.Name, Text: sk.Description}
			sigs := toolscan.Analyze(f)
			sigs = append(sigs, toolscan.ShadowSignals(f, skillNames)...)
			if fnd, ok := findingFromSignals("surface.a2a.skill-poisoning",
				fmt.Sprintf("Poisoned A2A skill description: %s", sk.Name), reqLabel, f, sigs, now); ok {
				out.findings = append(out.findings, fnd)
			}
		}

		out.findings = append(out.findings, a2aTrustFindings(reqLabel, card, now)...)
		return out
	}
	return out
}

var (
	strongA2ASchemes = map[string]bool{"oauth2": true, "openidconnect": true, "mutualtls": true, "mtls": true}
	weakA2ASchemes   = map[string]bool{"apikey": true, "basic": true, "http": true}
)

func a2aTrustFindings(reqLabel string, card a2aCard, now time.Time) []report.Finding {
	schemes := make([]string, 0, len(card.SecuritySchemes))
	seen := map[string]bool{}
	for _, s := range card.SecuritySchemes {
		t := strings.TrimSpace(s.Type)
		if t == "" {
			t = strings.TrimSpace(s.Scheme)
		}
		if t == "" || seen[strings.ToLower(t)] {
			continue
		}
		seen[strings.ToLower(t)] = true
		schemes = append(schemes, t)
	}
	sort.Strings(schemes)
	declared := len(schemes) > 0 || len(card.Security) > 0
	signed := len(card.Signatures) > 0

	var out []report.Finding
	if !declared {
		def := tech.Definition{
			ID:       "surface.a2a.unauthenticated",
			Title:    "Unauthenticated A2A interface declared on Agent Card",
			Category: "ASI07:2026 Insecure Inter-Agent Communication",
			Severity: tech.SeverityHigh,
			Description: "The published A2A Agent Card names no securitySchemes and no security requirement, " +
				"indicating any reachable caller can task the agent unless gated out-of-band.",
			Remediation: "Require verifiable authentication (OAuth2, OIDC or mTLS) on the A2A endpoint and declare it in securitySchemes/security on the Agent Card.",
		}
		out = append(out, report.NewFinding(def, report.Evidence{
			Prompt:   reqLabel,
			Response: fmt.Sprintf("agent=%q securitySchemes=[] security=[]", card.Name),
			Markers:  []string{"no security scheme declared"},
			Reason:   "Agent Card declares no authentication scheme or security requirement",
		}, 1.0, 1, now))
	} else if !signed {
		def := tech.Definition{
			ID:       "surface.a2a.unsigned-card",
			Title:    "Unsigned A2A Agent Card",
			Category: "ASI07:2026 Insecure Inter-Agent Communication",
			Severity: tech.SeverityMedium,
			Description: "The A2A Agent Card declares authentication but carries no JWS signature block, so " +
				"a peer cannot cryptographically distinguish it from a spoofed card served at the same path.",
			Remediation: "Sign the Agent Card with a JWS signature verified against a pinned key or JWKS before trusting advertised skills or endpoints.",
		}
		out = append(out, report.NewFinding(def, report.Evidence{
			Prompt:   reqLabel,
			Response: "declared schemes: " + strings.Join(schemes, ", ") + "; signatures: none",
			Markers:  []string{"signatures absent"},
			Reason:   "Agent Card carries no signature block",
		}, 1.0, 1, now))
	}

	if declared && onlyWeakSchemes(schemes) {
		def := tech.Definition{
			ID:       "surface.a2a.weak-auth-scheme",
			Title:    "A2A Agent Card declares only a shared-secret authentication scheme",
			Category: "ASI07:2026 Insecure Inter-Agent Communication",
			Severity: tech.SeverityLow,
			Description: fmt.Sprintf("The card declares only %s — a shared secret rather than a verifiable caller identity.",
				strings.Join(schemes, ", ")),
			Remediation: "Prefer workload-bound authentication (OAuth2, OIDC or mTLS) so each calling agent carries an attributable identity.",
		}
		out = append(out, report.NewFinding(def, report.Evidence{
			Prompt:   reqLabel,
			Response: "declared schemes: " + strings.Join(schemes, ", "),
			Markers:  schemes,
			Reason:   "Only weak/shared-secret schemes declared on the Agent Card: " + strings.Join(schemes, ", "),
		}, 1.0, 1, now))
	}
	return out
}

func onlyWeakSchemes(schemes []string) bool {
	if len(schemes) == 0 {
		return false
	}
	for _, s := range schemes {
		low := strings.ToLower(strings.TrimSpace(s))
		if strongA2ASchemes[low] || !weakA2ASchemes[low] {
			return false
		}
	}
	return true
}

func findingFromSignals(id, title, reqLabel string, f toolscan.Field, sigs []toolscan.Signal, now time.Time) (report.Finding, bool) {
	worst := toolscan.WorstSeverity(sigs)
	if worst == "" {
		return report.Finding{}, false
	}
	sev, _ := tech.ParseSeverity(worst)
	if toolscan.HasHighPrivilegeCapability(sigs) && sev != tech.SeverityCritical {
		sev = tech.SeverityCritical
	}

	var markers []string
	var reasons []string
	for _, s := range sigs {
		if s.Class == "capability" {
			continue
		}
		markers = append(markers, s.Rule)
		if s.Excerpt != "" {
			reasons = append(reasons, fmt.Sprintf("%s (%s): %q", s.Title, s.Rule, s.Excerpt))
		} else {
			reasons = append(reasons, fmt.Sprintf("%s (%s)", s.Title, s.Rule))
		}
	}

	def := tech.Definition{
		ID:       id,
		Title:    title,
		Category: "LLM01:2025 Prompt Injection",
		Severity: sev,
		Description: fmt.Sprintf("Advertised %s for %q contains %d static poisoning signal(s) that reach the model's context before any user prompt is processed.",
			f.Kind, f.Name, len(markers)),
		Remediation: "Sanitise and pin advertised tool/skill descriptions and server instructions. Strip invisible Unicode, disallow imperative instructions or external exfiltration URLs in metadata, and diff tool schemas before trusting updates.",
	}
	ev := report.Evidence{
		Prompt:   reqLabel + " (" + f.Kind + ": " + f.Name + ")",
		Response: truncate(f.Text, 1200),
		Markers:  markers,
		Reason:   strings.Join(reasons, "; "),
	}
	return report.NewFinding(def, ev, 0.95, 1, now), true
}

func doJSON(ctx context.Context, client *http.Client, method, rawURL string, defaultHeaders, headers map[string]string, body []byte) ([]byte, int, http.Header, error) {
	var r io.Reader
	if len(body) > 0 {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, r)
	if err != nil {
		return nil, 0, nil, err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "sixi-scanner")
	req.Header.Set("Cache-Control", "no-store")
	for k, v := range defaultHeaders {
		if k != "" && v != "" {
			req.Header.Set(k, v)
		}
	}
	for k, v := range headers {
		if k != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return raw, resp.StatusCode, resp.Header, err
}

func headerVal(h http.Header, key string) string {
	if h == nil {
		return ""
	}
	return h.Get(key)
}

func unwrapSSEJSON(raw []byte, contentType string) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return trimmed
	}
	isSSE := strings.Contains(strings.ToLower(contentType), "text/event-stream") ||
		bytes.HasPrefix(trimmed, []byte("event:")) ||
		bytes.HasPrefix(trimmed, []byte("data:"))
	if !isSSE {
		return trimmed
	}
	var cur []string
	var last, best string
	flush := func() {
		if len(cur) == 0 {
			return
		}
		cand := strings.TrimSpace(strings.Join(cur, "\n"))
		cur = cur[:0]
		if cand == "" || cand == "[DONE]" || !strings.HasPrefix(cand, "{") {
			return
		}
		last = cand
		if strings.Contains(cand, `"result"`) || strings.Contains(cand, `"error"`) {
			best = cand
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "data:") {
			cur = append(cur, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	flush()
	if best != "" {
		return []byte(best)
	}
	if last != "" {
		return []byte(last)
	}
	return trimmed
}

func httpClient(timeout time.Duration, insecure bool) *http.Client {
	c := &http.Client{Timeout: timeout}
	if insecure {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in for staging endpoints
		c.Transport = tr
	}
	return c
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "invalid-url"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func sortedKeys(m map[string]json.RawMessage) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

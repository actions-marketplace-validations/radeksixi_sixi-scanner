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
	"bytes"
	"context"
	"crypto/tls"
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

// Config controls a passive surface inspection.
type Config struct {
	URL      string
	Headers  map[string]string
	Timeout  time.Duration
	Insecure bool
	Now      func() time.Time
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

	scan := &report.Scan{
		SchemaVersion: report.SchemaVersion,
		StartedAt:     started,
		Target:        "surface " + redactURL(cfg.URL),
		TargetNotes: []string{
			"Passive surface inspection only: no adversarial prompts were sent. Findings reflect advertised MCP/A2A metadata and declared authentication posture.",
		},
		Options: report.Options{
			Rounds:      1,
			MaxAttempts: 1,
			Concurrency: 1,
			TechniqueIDs: []string{
				"surface.mcp.tool-poisoning",
				"surface.a2a.card-poisoning",
				"surface.a2a.trust-posture",
			},
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

	// Best-effort initialize to capture server instructions.
	var instructions string
	initBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "surface-init", "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "sixi-scanner", "version": "1.0"},
		},
	})
	out.requests++
	if raw, status, err := doJSON(ctx, client, http.MethodPost, cfg.URL, cfg.Headers, initBody); err == nil && status >= 200 && status < 300 {
		var env struct {
			JSONRPC string `json:"jsonrpc"`
			Result  *struct {
				Instructions string `json:"instructions"`
			} `json:"result"`
		}
		if json.Unmarshal(raw, &env) == nil && env.JSONRPC != "" && env.Result != nil {
			instructions = strings.TrimSpace(env.Result.Instructions)
		}
	}

	// tools/list decides whether the endpoint speaks MCP.
	listBody, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "surface-list", "method": "tools/list"})
	out.requests++
	raw, status, err := doJSON(ctx, client, http.MethodPost, cfg.URL, cfg.Headers, listBody)
	if err != nil {
		return out
	}

	var rpc struct {
		JSONRPC string `json:"jsonrpc"`
		Result  *struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				InputSchema struct {
					Properties map[string]json.RawMessage `json:"properties"`
				} `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &rpc) != nil || rpc.JSONRPC == "" {
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

	if rpc.Error != nil {
		out.detail = fmt.Sprintf("answered JSON-RPC error (HTTP %d): %s", status, truncate(rpc.Error.Message, 120))
		return out
	}
	if rpc.Result == nil {
		out.detail = "answered JSON-RPC with empty result"
		return out
	}

	names := make([]string, 0, len(rpc.Result.Tools))
	for _, t := range rpc.Result.Tools {
		names = append(names, t.Name)
	}
	out.detail = fmt.Sprintf("%d tool(s) advertised", len(names))
	if len(names) > 0 {
		out.detail += ": " + truncate(strings.Join(names, ", "), 160)
	}

	for _, t := range rpc.Result.Tools {
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
	return out
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
		raw, status, err := doJSON(ctx, client, http.MethodGet, cardURL, cfg.Headers, nil)
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

func doJSON(ctx context.Context, client *http.Client, method, rawURL string, headers map[string]string, body []byte) ([]byte, int, error) {
	var r io.Reader
	if len(body) > 0 {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, r)
	if err != nil {
		return nil, 0, err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "sixi-scanner")
	req.Header.Set("Cache-Control", "no-store")
	for k, v := range headers {
		if k != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return raw, resp.StatusCode, err
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

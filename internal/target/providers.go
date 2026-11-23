package target

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
)

// ============================================================================
// 1. OpenAI Responses API & Microsoft AI Foundry (/v1/responses)
// ============================================================================

// responsesTarget speaks the OpenAI Responses API (also used by Microsoft AI
// Foundry Agents and compatible gateways). Because the Responses API natively
// chains turns via previous_response_id, this connector implements Sessioner
// out of the box without needing client-side transcript replay.
type responsesTarget struct {
	cfg   Config
	model string

	mu      sync.Mutex
	prevIDs map[string]string // session ID -> last server response id
}

// NewResponses builds a target for an OpenAI Responses API / Microsoft Foundry endpoint.
func NewResponses(cfg Config) (Target, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("responses connector needs --url")
	}
	model := cfg.Extra["model"]
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &responsesTarget{
		cfg:     cfg,
		model:   model,
		prevIDs: map[string]string{},
	}, nil
}

func (r *responsesTarget) SupportsSessions() bool { return true }

func (r *responsesTarget) Describe() string {
	return fmt.Sprintf("responses %s", redactURL(r.cfg.URL))
}

func (r *responsesTarget) Send(ctx context.Context, prompt string) (Reply, error) {
	payload := map[string]any{
		"model":             r.model,
		"input":             prompt,
		"max_output_tokens": 512,
		"temperature":       0,
	}
	sid, hasSess := SessionFrom(ctx)
	if hasSess {
		r.mu.Lock()
		prev := r.prevIDs[sid]
		r.mu.Unlock()
		if prev != "" {
			payload["previous_response_id"] = prev
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Reply{}, fmt.Errorf("responses encode: %w", err)
	}

	status, raw, elapsed, err := post(ctx, r.cfg, body, "application/json")
	reply := Reply{Status: status, Latency: elapsed, Raw: raw}
	if err != nil {
		return reply, err
	}

	decoded, derr := decodeJSON(raw)
	if derr != nil {
		if status >= 200 && status < 300 {
			reply.Text = clip(stripHTML(raw))
		}
		return reply, nil
	}

	if e, ok := dig(decoded, "error.message"); ok && e != "" {
		return reply, fmt.Errorf("target returned an error: %s", e)
	}

	if hasSess {
		if id, ok := dig(decoded, "id"); ok && id != "" {
			r.mu.Lock()
			r.prevIDs[sid] = id
			r.mu.Unlock()
		}
	}

	text, calls := extractResponsesOutput(decoded)
	reply.Text = clip(text)
	reply.ToolCalls = calls
	return reply, nil
}

func extractResponsesOutput(decoded any) (string, []ToolCall) {
	obj, ok := decoded.(map[string]any)
	if !ok {
		return "", nil
	}
	var texts []string
	var calls []ToolCall

	if outList, ok := obj["output"].([]any); ok {
		for _, rawItem := range outList {
			item, ok := rawItem.(map[string]any)
			if !ok {
				continue
			}
			itemType, _ := item["type"].(string)
			switch itemType {
			case "function_call", "mcp_call", "tool_call":
				name, _ := item["name"].(string)
				args := stringifyArgs(item["arguments"])
				if name != "" {
					calls = append(calls, ToolCall{Name: name, Args: args})
				}
			case "message":
				if content, ok := item["content"].([]any); ok {
					for _, rawPart := range content {
						part, ok := rawPart.(map[string]any)
						if !ok {
							continue
						}
						if t, ok := part["text"].(string); ok && t != "" {
							texts = append(texts, t)
						} else if ref, ok := part["refusal"].(string); ok && ref != "" {
							texts = append(texts, ref)
						}
					}
				}
			}
		}
	}
	if len(texts) == 0 {
		if ot, ok := obj["output_text"].(string); ok && ot != "" {
			texts = append(texts, ot)
		}
	}
	return strings.Join(texts, "\n"), calls
}

// ============================================================================
// 2. Microsoft Azure OpenAI / Azure AI Foundry (--target azure)
// ============================================================================

// NewAzure builds an OpenAI-compatible target tailored for Azure OpenAI and
// Microsoft AI Foundry endpoints: it automatically injects AZURE_OPENAI_API_KEY
// as an `api-key` header if no api-key / Authorization header was passed, and
// ensures `api-version` is set on *.openai.azure.com URLs when omitted.
func NewAzure(cfg Config) (Target, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("azure connector needs --url")
	}
	cloned := cfg
	cloned.Headers = copyHeaderMap(cfg.Headers)
	if !hasHeaderFold(cloned.Headers, "api-key") && !hasHeaderFold(cloned.Headers, "authorization") {
		if k := strings.TrimSpace(os.Getenv("AZURE_OPENAI_API_KEY")); k != "" {
			cloned.Headers["api-key"] = k
		}
	}
	if u, err := url.Parse(cloned.URL); err == nil {
		if strings.HasSuffix(strings.ToLower(u.Hostname()), ".openai.azure.com") && u.Query().Get("api-version") == "" {
			q := u.Query()
			q.Set("api-version", "2024-10-21")
			u.RawQuery = q.Encode()
			cloned.URL = u.String()
		}
	}
	base, err := NewOpenAI(cloned)
	if err != nil {
		return nil, err
	}
	return &azureTarget{openaiTarget: base.(*openaiTarget)}, nil
}

type azureTarget struct {
	*openaiTarget
}

func (a *azureTarget) Describe() string {
	if a.stateful {
		return fmt.Sprintf("azure-openai (stateful) %s", redactURL(a.cfg.URL))
	}
	return fmt.Sprintf("azure-openai %s", redactURL(a.cfg.URL))
}

// ============================================================================
// 3. Google Gemini Native API & Vertex AI (--target gemini)
// ============================================================================

// geminiTarget speaks the Google Gemini generateContent REST wire format
// (`contents[].parts[]` -> `candidates[0].content.parts[]`), working against
// both generativelanguage.googleapis.com (with x-goog-api-key / GEMINI_API_KEY)
// and Vertex AI endpoints (with Authorization: Bearer).
type geminiTarget struct {
	cfg      Config
	stateful bool

	mu       sync.Mutex
	sessions map[string][]geminiContent
}

type geminiPart struct {
	Text string `json:"text,omitempty"`
}

type geminiContent struct {
	Role  string       `json:"role"`
	Parts []geminiPart `json:"parts"`
}

// NewGemini builds a target for a Google Gemini / Vertex AI generateContent endpoint.
func NewGemini(cfg Config) (Target, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("gemini connector needs --url")
	}
	cloned := cfg
	cloned.Headers = copyHeaderMap(cfg.Headers)
	if !hasHeaderFold(cloned.Headers, "x-goog-api-key") && !hasHeaderFold(cloned.Headers, "authorization") {
		if k := firstNonEmptyEnv("GEMINI_API_KEY", "GOOGLE_API_KEY"); k != "" {
			cloned.Headers["x-goog-api-key"] = k
		}
	}
	stateful := strings.EqualFold(strings.TrimSpace(cfg.Extra["stateful"]), "true")
	return &geminiTarget{
		cfg:      cloned,
		stateful: stateful,
		sessions: map[string][]geminiContent{},
	}, nil
}

func (g *geminiTarget) SupportsSessions() bool { return g.stateful }

func (g *geminiTarget) Describe() string {
	if g.stateful {
		return fmt.Sprintf("gemini (stateful) %s", redactURL(g.cfg.URL))
	}
	return fmt.Sprintf("gemini %s", redactURL(g.cfg.URL))
}

func (g *geminiTarget) Send(ctx context.Context, prompt string) (Reply, error) {
	var contents []geminiContent
	sid, hasSess := SessionFrom(ctx)
	if g.stateful && hasSess {
		g.mu.Lock()
		contents = append(contents, g.sessions[sid]...)
		g.mu.Unlock()
	}
	contents = append(contents, geminiContent{
		Role:  "user",
		Parts: []geminiPart{{Text: prompt}},
	})

	body, err := json.Marshal(map[string]any{
		"contents": contents,
		"generationConfig": map[string]any{
			"temperature":     0,
			"maxOutputTokens": 512,
		},
	})
	if err != nil {
		return Reply{}, fmt.Errorf("gemini encode: %w", err)
	}

	status, raw, elapsed, err := post(ctx, g.cfg, body, "application/json")
	reply := Reply{Status: status, Latency: elapsed, Raw: raw}
	if err != nil {
		return reply, err
	}

	decoded, derr := decodeJSON(raw)
	if derr != nil {
		if status >= 200 && status < 300 {
			reply.Text = clip(stripHTML(raw))
		}
		return reply, nil
	}
	if e, ok := dig(decoded, "error.message"); ok && e != "" {
		return reply, fmt.Errorf("target returned an error: %s", e)
	}

	text, calls := extractGeminiOutput(decoded)
	reply.Text = clip(text)
	reply.ToolCalls = calls

	if g.stateful && hasSess {
		g.mu.Lock()
		g.sessions[sid] = append(g.sessions[sid],
			geminiContent{Role: "user", Parts: []geminiPart{{Text: prompt}}},
			geminiContent{Role: "model", Parts: []geminiPart{{Text: reply.Text}}},
		)
		g.mu.Unlock()
	}
	return reply, nil
}

func extractGeminiOutput(decoded any) (string, []ToolCall) {
	cand := digAny(decoded, "candidates.0.content.parts")
	parts, ok := cand.([]any)
	if !ok {
		return "", nil
	}
	var texts []string
	var calls []ToolCall
	for _, rawPart := range parts {
		part, ok := rawPart.(map[string]any)
		if !ok {
			continue
		}
		if t, ok := part["text"].(string); ok && t != "" {
			texts = append(texts, t)
		}
		if fc, ok := part["functionCall"].(map[string]any); ok {
			name, _ := fc["name"].(string)
			args := stringifyArgs(fc["args"])
			if name != "" {
				calls = append(calls, ToolCall{Name: name, Args: args})
			}
		}
	}
	return strings.Join(texts, "\n"), calls
}

// ============================================================================
// 4. Anthropic Messages API (--target anthropic)
// ============================================================================

// anthropicTarget speaks the Anthropic Messages REST API (`POST /v1/messages`),
// extracting both text blocks and tool_use blocks into Reply.ToolCalls and
// supporting optional client-side multi-turn history (--stateful).
type anthropicTarget struct {
	cfg      Config
	model    string
	stateful bool

	mu       sync.Mutex
	sessions map[string][]chatMsg
}

// NewAnthropic builds a target for an Anthropic Messages endpoint.
func NewAnthropic(cfg Config) (Target, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("anthropic connector needs --url")
	}
	cloned := cfg
	cloned.Headers = copyHeaderMap(cfg.Headers)
	if !hasHeaderFold(cloned.Headers, "anthropic-version") {
		cloned.Headers["anthropic-version"] = "2023-06-01"
	}
	if !hasHeaderFold(cloned.Headers, "x-api-key") && !hasHeaderFold(cloned.Headers, "authorization") {
		if k := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")); k != "" {
			cloned.Headers["x-api-key"] = k
		}
	}
	model := cfg.Extra["model"]
	if model == "" {
		model = "claude-sonnet-4-5"
	}
	stateful := strings.EqualFold(strings.TrimSpace(cfg.Extra["stateful"]), "true")
	return &anthropicTarget{
		cfg:      cloned,
		model:    model,
		stateful: stateful,
		sessions: map[string][]chatMsg{},
	}, nil
}

func (a *anthropicTarget) SupportsSessions() bool { return a.stateful }

func (a *anthropicTarget) Describe() string {
	if a.stateful {
		return fmt.Sprintf("anthropic (stateful) %s", redactURL(a.cfg.URL))
	}
	return fmt.Sprintf("anthropic %s", redactURL(a.cfg.URL))
}

func (a *anthropicTarget) Send(ctx context.Context, prompt string) (Reply, error) {
	var msgs []chatMsg
	sid, hasSess := SessionFrom(ctx)
	if a.stateful && hasSess {
		a.mu.Lock()
		msgs = append(msgs, a.sessions[sid]...)
		a.mu.Unlock()
	}
	msgs = append(msgs, chatMsg{Role: "user", Content: prompt})

	body, err := json.Marshal(map[string]any{
		"model":       a.model,
		"max_tokens":  512,
		"temperature": 0,
		"messages":    msgs,
	})
	if err != nil {
		return Reply{}, fmt.Errorf("anthropic encode: %w", err)
	}

	status, raw, elapsed, err := post(ctx, a.cfg, body, "application/json")
	reply := Reply{Status: status, Latency: elapsed, Raw: raw}
	if err != nil {
		return reply, err
	}

	decoded, derr := decodeJSON(raw)
	if derr != nil {
		if status >= 200 && status < 300 {
			reply.Text = clip(stripHTML(raw))
		}
		return reply, nil
	}
	if e, ok := dig(decoded, "error.message"); ok && e != "" {
		return reply, fmt.Errorf("target returned an error: %s", e)
	}

	text, calls := extractAnthropicOutput(decoded)
	reply.Text = clip(text)
	reply.ToolCalls = calls

	if a.stateful && hasSess {
		a.mu.Lock()
		a.sessions[sid] = append(a.sessions[sid],
			chatMsg{Role: "user", Content: prompt},
			chatMsg{Role: "assistant", Content: reply.Text},
		)
		a.mu.Unlock()
	}
	return reply, nil
}

func extractAnthropicOutput(decoded any) (string, []ToolCall) {
	obj, ok := decoded.(map[string]any)
	if !ok {
		return "", nil
	}
	blocks, ok := obj["content"].([]any)
	if !ok {
		return "", nil
	}
	var texts []string
	var calls []ToolCall
	for _, rawBlock := range blocks {
		blk, ok := rawBlock.(map[string]any)
		if !ok {
			continue
		}
		switch blk["type"] {
		case "text":
			if t, ok := blk["text"].(string); ok && t != "" {
				texts = append(texts, t)
			}
		case "tool_use":
			name, _ := blk["name"].(string)
			args := stringifyArgs(blk["input"])
			if name != "" {
				calls = append(calls, ToolCall{Name: name, Args: args})
			}
		}
	}
	return strings.Join(texts, "\n"), calls
}

// ============================================================================
// Shared Helpers
// ============================================================================

func copyHeaderMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+2)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func hasHeaderFold(m map[string]string, want string) bool {
	for k := range m {
		if strings.EqualFold(k, want) {
			return true
		}
	}
	return false
}

func firstNonEmptyEnv(names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return ""
}

func stringifyArgs(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return fmt.Sprint(x)
		}
		return string(b)
	}
}

func init() {
	Register("responses", NewResponses)
	Register("azure", NewAzure)
	Register("gemini", NewGemini)
	Register("anthropic", NewAnthropic)
}

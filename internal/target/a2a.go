package target

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// a2aTarget speaks the Agent-to-Agent (A2A) JSON-RPC protocol over HTTP.
//
// A2A renamed the send verb at spec 0.3 (`tasks/send` -> `message/send`, part
// discriminator `type` -> `kind`), and both generations exist in the wild. The
// connector tries 0.3 first and falls back to 0.2 once on JSON-RPC -32601
// (method not found), pinning whichever dialect answered.
//
// It implements Sessioner: each session key from context maps to its own A2A
// task ID under a mutex, so parallel multi-turn probes never share a task.
type a2aTarget struct {
	cfg Config

	mu      sync.Mutex
	dialect a2aDialect
	tasks   map[string]string // sessionKey -> taskId (server-issued in v0.3, client-issued in v0.2)
}

type a2aDialect int

const (
	a2aAuto a2aDialect = iota
	a2aV03             // message/send, parts keyed "kind"
	a2aV02             // tasks/send, parts keyed "type"
)

const a2aMethodNotFound = -32601

// NewA2A builds an A2A JSON-RPC target.
func NewA2A(cfg Config) (Target, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("a2a connector needs --url")
	}
	return &a2aTarget{
		cfg:   cfg,
		tasks: map[string]string{},
	}, nil
}

// SupportsSessions implements Sessioner. A2A binds turns to a taskId, so multi-turn
// sequences execute inside one task per attempt.
func (a *a2aTarget) SupportsSessions() bool { return true }

func (a *a2aTarget) Describe() string { return "a2a " + redactURL(a.cfg.URL) }

func (a *a2aTarget) Send(ctx context.Context, prompt string) (Reply, error) {
	sessionKey, hasSession := SessionFrom(ctx)

	a.mu.Lock()
	dialect := a.dialect
	negotiated := dialect != a2aAuto
	if dialect == a2aAuto {
		dialect = a2aV03
	}
	taskID := ""
	if hasSession {
		taskID = a.tasks[sessionKey]
	}
	a.mu.Unlock()

	reply, serverTaskID, rpcCode, err := a.sendDialect(ctx, dialect, taskID, prompt)
	if err == nil {
		a.mu.Lock()
		if a.dialect == a2aAuto {
			a.dialect = dialect
		}
		if hasSession && serverTaskID != "" {
			a.tasks[sessionKey] = serverTaskID
		}
		a.mu.Unlock()
		return reply, nil
	}

	// Only an unnegotiated connector retries on v0.2, and only when the server explicitly
	// answered JSON-RPC -32601 (method not found).
	if !negotiated && dialect == a2aV03 && rpcCode == a2aMethodNotFound {
		v02TaskID := taskID
		if v02TaskID == "" {
			v02TaskID = newUUIDv4()
		}
		reply, _, _, retryErr := a.sendDialect(ctx, a2aV02, v02TaskID, prompt)
		if retryErr == nil {
			a.mu.Lock()
			a.dialect = a2aV02
			if hasSession {
				a.tasks[sessionKey] = v02TaskID
			}
			a.mu.Unlock()
			return reply, nil
		}
		return reply, retryErr
	}
	return reply, err
}

func (a *a2aTarget) sendDialect(ctx context.Context, dialect a2aDialect, taskID, prompt string) (Reply, string, int, error) {
	reqBody := a2aRequestBody(dialect, taskID, prompt)
	rawReq, err := json.Marshal(reqBody)
	if err != nil {
		return Reply{}, "", 0, fmt.Errorf("a2a encode: %w", err)
	}
	status, raw, elapsed, err := post(ctx, a.cfg, rawReq, "application/json")
	reply := Reply{Status: status, Latency: elapsed, Raw: raw}
	if err != nil {
		return reply, "", 0, err
	}
	if status == 401 || status == 403 {
		return reply, "", 0, fmt.Errorf("a2a: HTTP %d auth rejected", status)
	}
	if status == 429 || status >= 500 {
		return reply, "", 0, fmt.Errorf("a2a: target returned HTTP %d", status)
	}

	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return reply, "", 0, fmt.Errorf("a2a: malformed JSON-RPC reply: %w", err)
	}
	if len(env.Result) == 0 {
		code := 0
		msg := "missing result in JSON-RPC envelope"
		if env.Error != nil {
			code = env.Error.Code
			msg = fmt.Sprintf("JSON-RPC error %d: %s", env.Error.Code, env.Error.Message)
		}
		return reply, "", code, fmt.Errorf("a2a: %s", msg)
	}

	reply.Text = clip(extractA2AText(env.Result))
	return reply, extractA2ATaskID(env.Result), 0, nil
}

func a2aRequestBody(dialect a2aDialect, taskID, prompt string) map[string]any {
	if dialect == a2aV02 {
		if taskID == "" {
			taskID = newUUIDv4()
		}
		return map[string]any{
			"jsonrpc": "2.0",
			"id":      newUUIDv4(),
			"method":  "tasks/send",
			"params": map[string]any{
				"id": taskID,
				"message": map[string]any{
					"role":  "user",
					"parts": []map[string]any{{"type": "text", "text": prompt}},
				},
			},
		}
	}
	msg := map[string]any{
		"role":      "user",
		"messageId": newUUIDv4(),
		"parts":     []map[string]any{{"kind": "text", "text": prompt}},
	}
	if taskID != "" {
		msg["taskId"] = taskID
	}
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      newUUIDv4(),
		"method":  "message/send",
		"params":  map[string]any{"message": msg},
	}
}

func extractA2ATaskID(rawResult json.RawMessage) string {
	var res struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	if json.Unmarshal(rawResult, &res) != nil {
		return ""
	}
	if res.Kind == "task" && res.ID != "" {
		return res.ID
	}
	return ""
}

// extractA2AText reads text from the standard A2A reply layers: artifact parts,
// status.message parts, direct message parts, or the raw result JSON as fallback.
func extractA2AText(rawResult json.RawMessage) string {
	var res map[string]any
	if json.Unmarshal(rawResult, &res) != nil || res == nil {
		return string(rawResult)
	}
	if artifacts, ok := res["artifacts"].([]any); ok && len(artifacts) > 0 {
		if first, ok := artifacts[0].(map[string]any); ok {
			if txt := joinA2AParts(first["parts"]); txt != "" {
				return txt
			}
		}
	}
	if status, ok := res["status"].(map[string]any); ok {
		if msg, ok := status["message"].(map[string]any); ok {
			if txt := joinA2AParts(msg["parts"]); txt != "" {
				return txt
			}
		}
	}
	if txt := joinA2AParts(res["parts"]); txt != "" {
		return txt
	}
	return string(rawResult)
}

func joinA2AParts(parts any) string {
	list, ok := parts.([]any)
	if !ok {
		return ""
	}
	var texts []string
	for _, p := range list {
		part, ok := p.(map[string]any)
		if !ok {
			continue
		}
		kind, _ := part["kind"].(string)
		if kind == "" {
			kind, _ = part["type"].(string)
		}
		if kind == "text" {
			if t, ok := part["text"].(string); ok && t != "" {
				texts = append(texts, t)
			}
		}
	}
	return strings.Join(texts, " ")
}

// newUUIDv4 builds an RFC 4122 v4 UUID using crypto/rand without external dependencies.
func newUUIDv4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}

func init() { Register("a2a", NewA2A) }

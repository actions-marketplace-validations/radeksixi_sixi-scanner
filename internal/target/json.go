package target

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// jsonTarget reaches an agent that does not speak the OpenAI shape, by letting
// the user describe both the request and where the answer lives in the reply.
//
// It is the connector that makes the scanner usable against a bespoke internal
// agent without writing Go: point --body at a template and --reply-path at a
// dotted path, and it works. Including {{session}} or {{session_json}} in --body
// enables session-backed multi-turn probes on that endpoint, and --trace-path
// reads tool calls from a custom dotted path in the response.
type jsonTarget struct {
	cfg       Config
	bodyTpl   string
	replySep  string
	tracePath string
	hasSess   bool
}

// NewJSON builds a target from a request template and a dotted reply path.
func NewJSON(cfg Config) (Target, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("json connector needs --url")
	}
	tpl := cfg.Extra["body"]
	if tpl == "" {
		tpl = `{"message":{{json}}}`
	}
	path := cfg.Extra["reply-path"]
	if path == "" {
		path = "choices.0.message.content"
	}
	if _, ok := parseTemplate(tpl); !ok {
		return nil, fmt.Errorf("body template is not valid JSON once the prompt is substituted")
	}
	hasSess := strings.Contains(tpl, "{{session}}") || strings.Contains(tpl, "{{session_json}}")
	return &jsonTarget{
		cfg:       cfg,
		bodyTpl:   tpl,
		replySep:  path,
		tracePath: strings.TrimSpace(cfg.Extra["trace-path"]),
		hasSess:   hasSess,
	}, nil
}

// SupportsSessions implements Sessioner. A bespoke JSON endpoint can hold a
// conversation if and only if the caller's request template carries a session
// placeholder ({{session}} or {{session_json}}).
func (j *jsonTarget) SupportsSessions() bool { return j.hasSess }

func (j *jsonTarget) Send(ctx context.Context, prompt string) (Reply, error) {
	sessionID, _ := SessionFrom(ctx)
	body, err := renderTemplateWithSession(j.bodyTpl, prompt, sessionID)
	if err != nil {
		return Reply{}, fmt.Errorf("render body: %w", err)
	}

	status, raw, elapsed, err := post(ctx, j.cfg, body, "application/json")
	if err != nil {
		return Reply{Latency: elapsed}, err
	}

	reply := Reply{Status: status, Latency: elapsed, Raw: raw}

	decoded, derr := decodeJSON(raw)
	if derr != nil {
		if status >= 200 && status < 300 {
			reply.Text = clip(stripHTML(raw))
		}
		return reply, nil
	}

	text, ok := dig(decoded, j.replySep)
	if !ok {
		if e, found := dig(decoded, "error.message"); found {
			return reply, fmt.Errorf("target returned an error: %s", e)
		}
		return reply, fmt.Errorf("no value at reply path %q", j.replySep)
	}
	reply.Text = clip(text)

	// When --trace-path is named, read tool calls from that exact path. Otherwise
	// fall back to the sibling OpenAI message key so OpenAI-shaped responses keep
	// working with zero configuration.
	if j.tracePath != "" {
		if calls, known := ExtractToolCallsAt(decoded, j.tracePath); known {
			reply.ToolCalls = calls
		}
	} else if msg := digAny(decoded, "choices.0.message"); msg != nil {
		if calls, known := ExtractToolCalls(msg); known {
			reply.ToolCalls = calls
		}
	}
	return reply, nil
}

func (j *jsonTarget) Describe() string {
	return fmt.Sprintf("json %s (reply path %s)", redactURL(j.cfg.URL), j.replySep)
}

// renderTemplate substitutes {{prompt}} with the prompt escaped for the JSON
// string it sits in, and {{json}} with the prompt as a whole JSON string,
// quotes included. A template containing neither gets a
// {"message": ...} envelope, which is the common enough case to be worth
// guessing.
func renderTemplate(tpl, prompt string) ([]byte, error) {
	return renderTemplateWithSession(tpl, prompt, "")
}

// renderTemplateWithSession substitutes prompt placeholders plus optional
// {{session}} (escaped inner string) and {{session_json}} (full quoted JSON
// string) placeholders.
func renderTemplateWithSession(tpl, prompt, sessionID string) ([]byte, error) {
	out := tpl
	if strings.Contains(out, "{{session_json}}") {
		enc, err := json.Marshal(sessionID)
		if err != nil {
			return nil, err
		}
		out = strings.ReplaceAll(out, "{{session_json}}", string(enc))
	}
	if strings.Contains(out, "{{session}}") {
		enc, err := json.Marshal(sessionID)
		if err != nil {
			return nil, err
		}
		inner := string(enc[1 : len(enc)-1])
		out = strings.ReplaceAll(out, "{{session}}", inner)
	}

	// {{json}} substitutes the prompt as a JSON string, which is what keeps a
	// prompt containing a quote from breaking the body.
	if strings.Contains(out, "{{json}}") {
		encoded, err := json.Marshal(prompt)
		if err != nil {
			return nil, err
		}
		return []byte(strings.ReplaceAll(out, "{{json}}", string(encoded))), nil
	}

	// {{prompt}} sits inside a JSON string the template wrote — NewJSON rejects a template where
	// it does not — so it is substituted escaped, without the quotes {{json}} would add.
	if strings.Contains(out, "{{prompt}}") {
		encoded, err := json.Marshal(prompt)
		if err != nil {
			return nil, err
		}
		inner := string(encoded[1 : len(encoded)-1])
		return []byte(strings.ReplaceAll(out, "{{prompt}}", inner)), nil
	}

	// No placeholder at all: assume a bare {"message": ...} shape is wanted.
	encoded, err := json.Marshal(prompt)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`{"message":%s}`, encoded)), nil
}

// parseTemplate checks a template is JSON once the prompt (and optional session)
// placeholders are substituted.
func parseTemplate(tpl string) ([]byte, bool) {
	out := tpl
	if !strings.Contains(out, "{{prompt}}") && !strings.Contains(out, "{{json}}") {
		return nil, false
	}
	out = strings.ReplaceAll(out, "{{session_json}}", `"s"`)
	out = strings.ReplaceAll(out, "{{session}}", "s")
	out = strings.ReplaceAll(out, "{{json}}", `"x"`)
	out = strings.ReplaceAll(out, "{{prompt}}", "x")
	var v any
	return []byte(out), json.Unmarshal([]byte(out), &v) == nil
}

func init() { Register("json", NewJSON) }

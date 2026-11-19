package target

import (
	"encoding/json"
	"strings"
)

// ExtractToolCalls pulls the calls out of an OpenAI-shaped message or gateway envelope, and reports
// whether the trace could be read at all.
//
// The second return value is the one that matters. A reply with no tool calls and a connector that
// cannot see tool calls look identical if both collapse to nil, and conflating them makes every
// trace-based check inert exactly where it is needed: an agent that called nothing and said it had
// sent something. So "the message listed no calls" returns an empty non-nil slice with known=true,
// and only a message with no tool_calls key (or unreadable) returns known=false.
//
// It accepts every wire shape real gateways answer with:
//
//	[{"function": {"name": ..., "arguments": "<json>"}}]   OpenAI chat.completions style
//	[{"name": "send_email", "args": {...}}]                gateway style (args/arguments/input/parameters)
//	{"name": ..., "input": {...}}                          single call, not wrapped in a list
//	[{"name": "send_email", "to": "x@y"}]                  flat: arguments on the call itself
func ExtractToolCalls(msg any) ([]ToolCall, bool) {
	obj, ok := msg.(map[string]any)
	if !ok {
		return nil, false
	}
	raw, present := obj["tool_calls"]
	if !present {
		// No tool_calls key at all. That is NOT the same as an empty list: it means this endpoint
		// does not report a trace, and the agent may well have called anything. Returning
		// "known, empty" here is how a scanner ends up declaring lies it has no evidence for.
		return nil, false
	}
	return ExtractToolCallsFromValue(raw), true
}

// ExtractToolCallsAt reads a tool-call trace from an arbitrary dotted path in a decoded JSON body.
//
// Returns (nil, false) when path is empty or does not resolve in doc — the endpoint reported no
// trace at that path — and (calls, true) when the path resolved (with an empty non-nil slice when
// the resolved value is empty).
func ExtractToolCallsAt(doc any, path string) ([]ToolCall, bool) {
	if path == "" || doc == nil {
		return nil, false
	}
	v, found := digAnyFound(doc, path)
	if !found {
		return nil, false
	}
	return ExtractToolCallsFromValue(v), true
}

// ExtractToolCallsFromValue parses a resolved tool-call trace value (list or single object) into a
// non-nil slice of ToolCall.
func ExtractToolCallsFromValue(v any) []ToolCall {
	if v == nil {
		return []ToolCall{}
	}
	items, ok := v.([]any)
	if !ok {
		if _, isObj := v.(map[string]any); isObj {
			items = []any{v}
		} else {
			return []ToolCall{}
		}
	}
	out := make([]ToolCall, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := toolCallName(entry)
		if name == "" {
			continue
		}
		out = append(out, ToolCall{
			Name: name,
			Args: toolCallArgs(entry),
		})
	}
	return out
}

// toolCallName reads the call's name from a nested `function` wrapper or from the object itself.
func toolCallName(m map[string]any) string {
	if fn, ok := m["function"].(map[string]any); ok {
		if s, ok := fn["name"].(string); ok && s != "" {
			return s
		}
	}
	for _, k := range []string{"name", "tool", "tool_name", "action", "command"} {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// toolCallArgs extracts arguments as a JSON string across OpenAI, gateway, and flat call shapes.
func toolCallArgs(m map[string]any) string {
	if fn, ok := m["function"].(map[string]any); ok {
		if s, found := argsJSONFrom(fn); found {
			return s
		}
	}
	if s, found := argsJSONFrom(m); found {
		return s
	}
	// Flat shape: {"name": "send_email", "to": "a@b.test", "subject": "hi"}.
	flat := map[string]any{}
	for k, val := range m {
		switch k {
		case "name", "function", "tool", "tool_name", "action", "command",
			"id", "index", "type", "role", "finish_reason":
			continue
		}
		flat[k] = val
	}
	if len(flat) == 0 {
		return ""
	}
	b, err := json.Marshal(flat)
	if err != nil {
		return ""
	}
	return string(b)
}

func argsJSONFrom(m map[string]any) (string, bool) {
	for _, k := range []string{"arguments", "args", "input", "parameters"} {
		raw, ok := m[k]
		if !ok || raw == nil {
			continue
		}
		switch a := raw.(type) {
		case string:
			return a, true
		default:
			if b, err := json.Marshal(a); err == nil {
				return string(b), true
			}
		}
	}
	return "", false
}

// digAny walks a dotted path and returns the value found there, without insisting it is a string.
// dig returns only leaves it can render as text, which is no use for a tool-call object.
func digAny(v any, path string) any {
	val, _ := digAnyFound(v, path)
	return val
}

// digAnyFound is digAny plus a boolean distinguishing "key absent" from "key present with nil value".
func digAnyFound(v any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}
	cur := v
	for _, seg := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[seg]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			i, err := atoi(seg)
			if err != nil || i < 0 || i >= len(node) {
				return nil, false
			}
			cur = node[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

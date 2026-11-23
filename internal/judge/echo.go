package judge

import (
	"encoding/json"
	"strings"
)

// diagnosticEchoCues identify error, validation, or empty-lookup replies where a
// non-LLM tool or validator verbatim quotes the rejected caller input back in its
// diagnostic message (for example Pydantic "1 validation error ... input_value={'city': '<prompt>'}"
// or "Error: File not found — <prompt>" or "No documents matched the query '<prompt>'").
var diagnosticEchoCues = []string{
	"[mcp tool error]",
	"[mcp error]",
	"validation error",
	"field required",
	"input_value=",
	"error executing tool",
	"error: file not found",
	"file not found",
	"directory not found",
	"error: permission denied",
	"permission denied",
	"access denied",
	"no documents matched",
	"no files matching",
	"no results found",
	"no matching",
	"invalid argument",
	"invalid input",
	"invalid parameter",
	"unknown city",
	"unknown location",
}

// minEchoPromptLen prevents short strings (such as single words or numbers) from
// ever being stripped as diagnostic echoes.
const minEchoPromptLen = 24

// StripDiagnosticEcho removes a verbatim (or JSON/Python-escaped) reflection of
// prompt from response when the response is an explicit tool error (toolError == true)
// or a short diagnostic/lookup-miss envelope around the prompt.
//
// Any content outside the echoed prompt is preserved intact: if an error message
// leaks a real secret or internal configuration that was NOT in the caller's prompt,
// Disclosure still sees and flags it. Plain non-diagnostic echoes (such as the
// built-in `--target echo` demo) are left untouched.
func StripDiagnosticEcho(prompt, response string, toolError bool) (string, bool) {
	p := strings.TrimSpace(prompt)
	if len(p) < minEchoPromptLen || len(response) == 0 {
		return response, false
	}

	candidates := echoVariants(p)
	matched := ""
	for _, cand := range candidates {
		if len(cand) >= minEchoPromptLen && strings.Contains(response, cand) {
			matched = cand
			break
		}
	}
	if matched == "" {
		return response, false
	}

	remainder := strings.ReplaceAll(response, matched, "")
	if toolError {
		return strings.TrimSpace(remainder), true
	}

	// Without an explicit ToolError bit, require BOTH a short diagnostic wrapper
	// around the echoed input AND an explicit error / validation / empty-lookup cue
	// so genuine LLM answers that happen to quote the prompt are never stripped.
	trimmedRem := strings.TrimSpace(remainder)
	if len(trimmedRem) > 260 {
		return response, false
	}
	lowRem := strings.ToLower(trimmedRem)
	for _, cue := range diagnosticEchoCues {
		if strings.Contains(lowRem, cue) {
			return trimmedRem, true
		}
	}
	return response, false
}

// echoVariants returns the verbatim prompt plus the JSON-escaped and
// Python-repr-escaped single-line forms that validators (Pydantic, FastMCP,
// json.dumps) emit when echoing an invalid string argument.
func echoVariants(p string) []string {
	out := []string{p}
	if b, err := json.Marshal(p); err == nil && len(b) >= 2 {
		// Unwrapped JSON string content (newlines become \n, quotes become \").
		escaped := string(b[1 : len(b)-1])
		if escaped != p {
			out = append(out, escaped)
		}
	}
	// Python repr() style: newlines -> \n, single quotes -> \' (when double quotes absent).
	pyEsc := strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\r", "\\r", "\t", "\\t", "'", "\\'").Replace(p)
	if pyEsc != p {
		out = append(out, pyEsc)
	}
	pyDouble := strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\r", "\\r", "\t", "\\t").Replace(p)
	if pyDouble != p && pyDouble != pyEsc {
		out = append(out, pyDouble)
	}
	return out
}

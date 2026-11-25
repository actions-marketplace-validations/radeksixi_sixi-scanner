package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// LayaGuardPack is the machine-readable regression guardrail bundle exported
// by `sixi-scanner --export-laya` and loaded directly by `laya-as-judge`
// (`load_sixi_scanner_rules` / `laya-judge serve --rules-file` / `laya-judge verify-sixi`).
type LayaGuardPack struct {
	SchemaVersion   string               `json:"schema_version"`
	Generator       string               `json:"generator"`
	ScannerVersion  string               `json:"scanner_version,omitempty"`
	Target          string               `json:"target"`
	ExportedAt      string               `json:"exported_at"`
	Rules           []LayaGuardRule      `json:"rules"`
	RegressionCases []LayaRegressionCase `json:"regression_cases"`
}

// LayaGuardRule is one deterministic policy rule compiled by `laya-as-judge`
// into a `PolicyRuleFn` for JudgedDecisionEngine, FastMCP, or LangGraph.
type LayaGuardRule struct {
	ID                   string   `json:"id"`
	Fingerprint          string   `json:"fingerprint"`
	TechniqueID          string   `json:"technique_id"`
	Severity             string   `json:"severity"`
	Kind                 string   `json:"kind"` // prompt_block | tool_block | mcp_surface_block | output_block
	Action               string   `json:"action"`
	Reason               string   `json:"reason"`
	Title                string   `json:"title"`
	PromptExact          string   `json:"prompt_exact,omitempty"`
	PromptSHA256         string   `json:"prompt_sha256,omitempty"`
	PromptPhrases        []string `json:"prompt_phrases,omitempty"`
	BlockedTools         []string `json:"blocked_tools,omitempty"`
	BlockedArgSubstrings []string `json:"blocked_arg_substrings,omitempty"`
	ResponseMarkers      []string `json:"response_markers,omitempty"`
	EvidenceBasis        string   `json:"evidence_basis,omitempty"`
}

// LayaRegressionCase is a replayable attack vector paired with expected_gate="block".
type LayaRegressionCase struct {
	ID               string         `json:"id"`
	TechniqueID      string         `json:"technique_id"`
	Severity         string         `json:"severity"`
	Kind             string         `json:"kind"`
	Prompt           string         `json:"prompt"`
	ExpectedGate     string         `json:"expected_gate"`
	ToolName         string         `json:"tool_name,omitempty"`
	ToolArguments    map[string]any `json:"tool_arguments,omitempty"`
	BaselineResponse string         `json:"baseline_response,omitempty"`
}

var (
	reLayaTitleTool   = regexp.MustCompile(`:\s*([A-Za-z0-9_\-\.]+)\s*$`)
	reLayaCallTool    = regexp.MustCompile(`\b([a-zA-Z_][a-zA-Z0-9_\-]*)\s*\(`)
	reLayaSpaces      = regexp.MustCompile(`\s+`)
	reLayaQuotedToken = regexp.MustCompile(`"([^"]{3,96})"`)
	reLayaPolicyCode  = regexp.MustCompile(`^[A-Z0-9_]{6,}$`)
)

// BuildLayaGuardPack converts every finding in scan into deterministic
// guardrail rules and regression cases for `laya-as-judge`.
func BuildLayaGuardPack(scan *Scan) LayaGuardPack {
	exportedAt := scan.FinishedAt
	if exportedAt.IsZero() {
		exportedAt = time.Now().UTC()
	}
	pack := LayaGuardPack{
		SchemaVersion:   "1.0",
		Generator:       "sixi-scanner",
		ScannerVersion:  scan.Version,
		Target:          scan.Target,
		ExportedAt:      exportedAt.UTC().Format(time.RFC3339),
		Rules:           make([]LayaGuardRule, 0, len(scan.Findings)),
		RegressionCases: make([]LayaRegressionCase, 0, len(scan.Findings)),
	}

	for i, f := range scan.Findings {
		fpShort := f.Fingerprint
		if len(fpShort) > 8 {
			fpShort = fpShort[:8]
		}
		if fpShort == "" {
			fpShort = fmt.Sprintf("f%03d", i+1)
		}
		ruleID := fmt.Sprintf("sixi-rule-%03d-%s", i+1, fpShort)
		kind := "prompt_block"
		var blockedTools []string
		var blockedArgs []string

		switch {
		case strings.HasPrefix(f.TechniqueID, "surface.mcp."):
			kind = "mcp_surface_block"
			if m := reLayaTitleTool.FindStringSubmatch(f.Title); len(m) == 2 {
				blockedTools = append(blockedTools, m[1])
			}
		case f.EvidenceBasis == "trace" || strings.HasPrefix(f.TechniqueID, "policy."):
			kind = "tool_block"
			if m := reLayaCallTool.FindStringSubmatch(f.Evidence.Reason + " " + f.Evidence.Response); len(m) == 2 {
				blockedTools = append(blockedTools, m[1])
			}
			seenArg := map[string]bool{}
			addArg := func(s string) {
				s = strings.TrimSpace(s)
				if len(s) < 4 || seenArg[strings.ToLower(s)] {
					return
				}
				seenArg[strings.ToLower(s)] = true
				blockedArgs = append(blockedArgs, s)
			}
			// Extract concrete offending argument values (forbidden tables, unauthorized accounts,
			// emails, SQLi patterns) quoted inside the trace-policy violation reason.
			for _, m := range reLayaQuotedToken.FindAllStringSubmatch(f.Evidence.Reason, -1) {
				val := strings.TrimSpace(m[1])
				if val != "" && !reLayaPolicyCode.MatchString(val) {
					addArg(val)
				}
			}
			for _, mk := range f.Evidence.Markers {
				mk = strings.TrimSpace(mk)
				if len(mk) < 4 {
					continue
				}
				// Skip abstract policy violation codes when concrete argument substrings were extracted.
				if reLayaPolicyCode.MatchString(mk) && len(blockedArgs) > 0 {
					continue
				}
				addArg(mk)
			}
		}

		promptExact := ""
		promptHash := ""
		var phrases []string
		if kind != "mcp_surface_block" {
			promptExact = strings.TrimSpace(f.Evidence.Prompt)
			if promptExact != "" {
				promptHash = sha256Norm(promptExact)
				phrases = extractDistinctivePhrases(promptExact, 4)
			}
		}

		markers := make([]string, 0, len(f.Evidence.Markers))
		for _, mk := range f.Evidence.Markers {
			if s := strings.TrimSpace(mk); s != "" {
				markers = append(markers, s)
			}
		}

		rule := LayaGuardRule{
			ID:                   ruleID,
			Fingerprint:          f.Fingerprint,
			TechniqueID:          f.TechniqueID,
			Severity:             string(f.Severity),
			Kind:                 kind,
			Action:               "block",
			Reason:               "sixi_scanner_regression:" + f.TechniqueID,
			Title:                f.Title,
			PromptExact:          promptExact,
			PromptSHA256:         promptHash,
			PromptPhrases:        phrases,
			BlockedTools:         blockedTools,
			BlockedArgSubstrings: blockedArgs,
			ResponseMarkers:      markers,
			EvidenceBasis:        f.EvidenceBasis,
		}
		pack.Rules = append(pack.Rules, rule)

		rc := LayaRegressionCase{
			ID:               ruleID,
			TechniqueID:      f.TechniqueID,
			Severity:         string(f.Severity),
			Kind:             kind,
			Prompt:           strings.TrimSpace(f.Evidence.Prompt),
			ExpectedGate:     "block",
			BaselineResponse: clipRunes(f.Evidence.Response, 300),
		}
		if len(blockedTools) > 0 {
			rc.ToolName = blockedTools[0]
		}
		if len(blockedArgs) > 0 {
			rc.ToolArguments = map[string]any{"sample": blockedArgs[0]}
		}
		pack.RegressionCases = append(pack.RegressionCases, rc)
	}

	return pack
}

// WriteLayaGuardPack encodes the exported guardrail pack as indented JSON.
func WriteLayaGuardPack(w io.Writer, scan *Scan) error {
	pack := BuildLayaGuardPack(scan)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(pack)
}

func normLayaText(s string) string {
	return reLayaSpaces.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), " ")
}

func sha256Norm(s string) string {
	sum := sha256.Sum256([]byte(normLayaText(s)))
	return hex.EncodeToString(sum[:])[:16]
}

func extractDistinctivePhrases(prompt string, limit int) []string {
	lines := strings.FieldsFunc(prompt, func(r rune) bool { return r == '\n' || r == '\r' })
	seen := map[string]bool{}
	var out []string
	for _, line := range lines {
		n := normLayaText(line)
		if len(n) < 18 {
			continue
		}
		if len(n) > 160 {
			n = n[:160]
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
			if len(out) >= limit {
				return out
			}
		}
	}
	if len(out) == 0 {
		n := normLayaText(prompt)
		if len(n) >= 12 {
			if len(n) > 160 {
				n = n[:160]
			}
			out = append(out, n)
		}
	}
	return out
}

func clipRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

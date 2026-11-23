// Package toolscan is a static poisoning check over an agent's advertised surface.
//
// It reads only what a target publishes to any client — an MCP server's tool
// descriptions and server instructions, or an A2A Agent Card's agent and skill
// descriptions — and never sends an adversarial prompt. It catches the passive,
// supply-chain half of MCP/A2A tool poisoning: hidden Unicode, BiDi overrides,
// Tag-Plane smuggling, base64-encoded instructions, exfiltration URLs, injected
// control tags (<IMPORTANT>, <instructions>, <system>), and cross-tool shadowing.
//
// Pure Go standard library, zero dependencies.
package toolscan

import (
	"sort"
	"strings"
)

// Field-kind labels naming which advertised surface a piece of text came from.
const (
	KindToolName           = "tool.name"
	KindToolDescription    = "tool.description"
	KindSkillDescription   = "skill.description"
	KindServerInstructions = "server.instructions"
)

// maxExcerpt bounds matched evidence so a hostile description cannot turn one
// finding into megabytes on the wire.
const maxExcerpt = 120

// maxScan caps how much of one metadata field is examined.
const maxScan = 64 << 10

// Field is one advertised text surface to analyse.
type Field struct {
	Kind       string
	Name       string
	Text       string
	SchemaKeys []string
}

// Signal is one detection over one advertised field.
type Signal struct {
	Rule       string   `json:"rule"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Class      string   `json:"class"` // injection | hidden | encoded | exfil | shadow | capability
	Labels     []string `json:"labels,omitempty"`
	Provenance []string `json:"provenance,omitempty"`
	Field      string   `json:"field"`
	Name       string   `json:"name"`
	Offset     int      `json:"offset"`
	Excerpt    string   `json:"excerpt,omitempty"`
}

// Analyze returns every signal found in one advertised field.
//
// Structural detectors (hidden Unicode, base64, exfil URLs) run over raw text;
// injection/steering regexes run over an invisible-stripped copy so zero-width
// evasion ("ig<ZWSP>nore previous") still matches while offsets map back to raw.
func Analyze(f Field) []Signal {
	text := f.Text
	if len(text) > maxScan {
		text = text[:maxScan]
	}
	var out []Signal

	out = append(out, hiddenUnicode(text, f)...)
	out = append(out, encodedPayloads(text, f)...)
	out = append(out, exfilURLs(text, f)...)

	folded, mapBack := stripInvisible(text)
	for _, r := range rulesFor(f.Kind) {
		for _, loc := range r.re.FindAllStringIndex(folded, -1) {
			rawOff := mapBack(loc[0])
			out = append(out, Signal{
				Rule:       r.id,
				Title:      r.title,
				Severity:   r.severity,
				Class:      r.class,
				Labels:     r.labels,
				Provenance: r.provenance,
				Field:      f.Kind,
				Name:       f.Name,
				Offset:     rawOff,
				Excerpt:    excerptAt(text, rawOff, mapBack(loc[1])-rawOff),
			})
		}
	}

	out = append(out, capabilitySignals(f)...)
	sortSignals(out)
	return out
}

// ShadowSignals reports whether one tool or skill's advertised text steers an
// agent toward or away from another advertised tool by name, or injects a
// mandatory prerequisite/post-hook hijacking another advertised tool.
func ShadowSignals(f Field, otherNames []string) []Signal {
	if f.Kind != KindToolDescription && f.Kind != KindSkillDescription {
		return nil
	}
	text := f.Text
	if len(text) > maxScan {
		text = text[:maxScan]
	}
	folded, mapBack := stripInvisible(text)
	low := strings.ToLower(folded)
	hasSteer := steeringPattern.MatchString(low)
	hasPrereq := prereqHookPattern.MatchString(low) && prereqObligPattern.MatchString(low)
	if !hasSteer && !hasPrereq {
		return nil
	}
	var out []Signal
	for _, other := range otherNames {
		other = strings.TrimSpace(other)
		if len(other) < 4 || strings.EqualFold(other, f.Name) {
			continue
		}
		if idx := wordIndex(low, strings.ToLower(other)); idx >= 0 {
			if hasSteer {
				out = append(out, Signal{
					Rule:       "shadow.names_other_tool",
					Title:      "Tool description steers toward or away from another tool by name",
					Severity:   "high",
					Class:      "shadow",
					Labels:     []string{"tool_shadowing"},
					Provenance: []string{"MCP07", "ASI02"},
					Field:      f.Kind,
					Name:       f.Name,
					Offset:     mapBack(idx),
					Excerpt:    excerptAt(text, mapBack(idx), len(other)),
				})
			}
			if hasPrereq {
				out = append(out, Signal{
					Rule:       "shadow.prerequisite_hijack",
					Title:      "Tool description injects a mandatory pre/post-hook on another tool by name",
					Severity:   "high",
					Class:      "shadow",
					Labels:     []string{"tool_shadowing", "prerequisite_hijack"},
					Provenance: []string{"MCP07", "ASI02"},
					Field:      f.Kind,
					Name:       f.Name,
					Offset:     mapBack(idx),
					Excerpt:    excerptAt(text, mapBack(idx), len(other)),
				})
			}
		}
	}
	sortSignals(out)
	return out
}

// WorstSeverity returns the highest severity among defect-class signals, or ""
// when there is no defect (capability-only signals are context, not defects).
func WorstSeverity(signals []Signal) string {
	worst := ""
	for _, s := range signals {
		if s.Class == "capability" {
			continue
		}
		if severityRank(s.Severity) > severityRank(worst) {
			worst = s.Severity
		}
	}
	return worst
}

// HasHighPrivilegeCapability reports whether signals include a dangerous
// execution or secret-access capability that elevates a poisoning finding.
func HasHighPrivilegeCapability(signals []Signal) bool {
	for _, s := range signals {
		if s.Class != "capability" {
			continue
		}
		for _, lbl := range s.Labels {
			switch lbl {
			case "shell_access", "code_execution", "credential_access":
				return true
			}
		}
	}
	return false
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func sortSignals(s []Signal) {
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].Offset != s[j].Offset {
			return s[i].Offset < s[j].Offset
		}
		return severityRank(s[i].Severity) > severityRank(s[j].Severity)
	})
}

func excerptAt(text string, off, length int) string {
	if off < 0 || off > len(text) {
		return ""
	}
	end := off + length
	if end < off {
		end = off
	}
	if end-off < maxExcerpt {
		end = off + maxExcerpt
	}
	if end > len(text) {
		end = len(text)
	}
	if end-off > maxExcerpt {
		end = off + maxExcerpt
	}
	for end > off && end < len(text) && !utf8Start(text[end]) {
		end--
	}
	return strings.TrimSpace(text[off:end])
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

func wordIndex(haystack, needle string) int {
	if needle == "" {
		return -1
	}
	from := 0
	for {
		i := strings.Index(haystack[from:], needle)
		if i < 0 {
			return -1
		}
		at := from + i
		before := at == 0 || !isWordByte(haystack[at-1])
		afterPos := at + len(needle)
		after := afterPos >= len(haystack) || !isWordByte(haystack[afterPos])
		if before && after {
			return at
		}
		from = at + 1
	}
}

func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_'
}

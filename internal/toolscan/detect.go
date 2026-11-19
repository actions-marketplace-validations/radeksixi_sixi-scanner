package toolscan

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

var invisibleRunes = map[rune]string{
	0x200B: "ZWSP", 0x200C: "ZWNJ", 0x200D: "ZWJ", 0x2060: "WORD-JOINER",
	0xFEFF: "BOM", 0x00AD: "SOFT-HYPHEN",
	0x202A: "LRE", 0x202B: "RLE", 0x202C: "PDF", 0x202D: "LRO", 0x202E: "RLO",
	0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI",
}

func isInvisible(r rune) bool {
	if _, ok := invisibleRunes[r]; ok {
		return true
	}
	return r >= 0xE0000 && r <= 0xE007F
}

func hiddenUnicode(text string, f Field) []Signal {
	seen := map[string]int{}
	order := []string{}
	for i, r := range text {
		if !isInvisible(r) {
			continue
		}
		name := invisibleRunes[r]
		if name == "" {
			name = "TAG-PLANE"
		}
		if _, ok := seen[name]; !ok {
			seen[name] = i
			order = append(order, name)
		}
	}
	if len(order) == 0 {
		return nil
	}
	sort.Slice(order, func(i, j int) bool { return seen[order[i]] < seen[order[j]] })
	out := make([]Signal, 0, len(order))
	for _, name := range order {
		sev := "high"
		if name == "RLO" || name == "RLE" || name == "LRO" || name == "TAG-PLANE" {
			sev = "critical"
		}
		out = append(out, Signal{
			Rule:       "hidden.invisible_unicode",
			Title:      "Invisible Unicode in advertised text: " + name,
			Severity:   sev,
			Class:      "hidden",
			Labels:     []string{"hidden_unicode", strings.ToLower(name)},
			Provenance: []string{"MCP04", "ASI03"},
			Field:      f.Kind,
			Name:       f.Name,
			Offset:     seen[name],
			Excerpt:    visibleContext(text, seen[name]),
		})
	}
	return out
}

func visibleContext(text string, off int) string {
	start := off - 24
	if start < 0 {
		start = 0
	}
	for start > 0 && !utf8Start(text[start]) {
		start--
	}
	end := off + 24
	if end > len(text) {
		end = len(text)
	}
	for end < len(text) && !utf8Start(text[end]) {
		end++
	}
	var b strings.Builder
	for _, r := range text[start:end] {
		if isInvisible(r) {
			name := invisibleRunes[r]
			if name == "" {
				name = fmt.Sprintf("U+%04X", r)
			}
			b.WriteString("[" + name + "]")
		} else {
			b.WriteRune(r)
		}
	}
	s := strings.TrimSpace(b.String())
	if len(s) > maxExcerpt {
		s = s[:maxExcerpt]
	}
	return s
}

func encodedPayloads(text string, f Field) []Signal {
	var out []Signal
	for _, tok := range base64Candidates(text) {
		decoded, ok := decodePrintable(tok.text)
		if !ok {
			continue
		}
		out = append(out, Signal{
			Rule:       "encoded.base64_payload",
			Title:      "Base64 token that decodes to text",
			Severity:   "high",
			Class:      "encoded",
			Labels:     []string{"base64_instruction"},
			Provenance: []string{"MCP04", "ASI03"},
			Field:      f.Kind,
			Name:       f.Name,
			Offset:     tok.offset,
			Excerpt:    "decodes to: " + boundExcerpt(decoded),
		})
	}
	return out
}

type token struct {
	text   string
	offset int
}

func base64Candidates(text string) []token {
	var out []token
	n := len(text)
	i := 0
	for i < n {
		if !isBase64Byte(text[i]) || (i > 0 && isBase64Byte(text[i-1])) {
			i++
			continue
		}
		j := i
		for j < n && isBase64Byte(text[j]) {
			j++
		}
		run := text[i:j]
		if len(run) >= 20 {
			out = append(out, token{text: run, offset: i})
		}
		i = j
	}
	return out
}

func isBase64Byte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '/' || b == '='
}

func decodePrintable(tok string) (string, bool) {
	var raw []byte
	var err error
	if raw, err = base64.StdEncoding.DecodeString(tok); err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(tok, "=")); err != nil {
			return "", false
		}
	}
	if len(raw) < 16 || len(raw) > 2048 {
		return "", false
	}
	if !utf8.Valid(raw) {
		return "", false
	}
	printable := 0
	for _, r := range string(raw) {
		if r == '\n' || r == '\t' || r == '\r' || (r >= 0x20 && r != 0x7f) {
			printable++
		}
	}
	if float64(printable)/float64(utf8.RuneCount(raw)) < 0.85 {
		return "", false
	}
	return string(raw), true
}

func exfilURLs(text string, f Field) []Signal {
	var out []Signal
	for _, loc := range exfilURLPattern.FindAllStringIndex(text, -1) {
		sev := "high"
		if f.Kind == KindServerInstructions {
			sev = "critical"
		}
		out = append(out, Signal{
			Rule:       "exfil.url_query",
			Title:      "URL with a sensitive query parameter",
			Severity:   sev,
			Class:      "exfil",
			Labels:     []string{"exfil_url"},
			Provenance: []string{"MCP04", "ASI03"},
			Field:      f.Kind,
			Name:       f.Name,
			Offset:     loc[0],
			Excerpt:    excerptAt(text, loc[0], loc[1]-loc[0]),
		})
	}
	return out
}

func capabilitySignals(f Field) []Signal {
	if f.Kind != KindToolName && f.Kind != KindToolDescription {
		return nil
	}
	combined := f.Name + " " + f.Text
	if len(f.SchemaKeys) > 0 {
		combined += " " + strings.Join(f.SchemaKeys, " ")
	}
	seen := map[string]bool{}
	var out []Signal
	for _, c := range capabilityRules {
		if seen[c.label] {
			continue
		}
		if c.re.MatchString(combined) {
			seen[c.label] = true
			out = append(out, Signal{
				Rule:     "capability." + c.label,
				Title:    "Capability surface: " + c.label,
				Severity: "low",
				Class:    "capability",
				Labels:   []string{c.label},
				Field:    f.Kind,
				Name:     f.Name,
			})
		}
	}
	return out
}

func boundExcerpt(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxExcerpt {
		return s
	}
	end := maxExcerpt
	for end > 0 && !utf8Start(s[end]) {
		end--
	}
	return s[:end]
}

func stripInvisible(text string) (string, func(int) int) {
	var b strings.Builder
	b.Grow(len(text))
	index := make([]int, 0, len(text))
	for i, r := range text {
		if isInvisible(r) {
			continue
		}
		for k := 0; k < utf8.RuneLen(r); k++ {
			index = append(index, i)
		}
		b.WriteRune(r)
	}
	stripped := b.String()
	mapBack := func(off int) int {
		if off < 0 {
			return 0
		}
		if off >= len(index) {
			return len(text)
		}
		return index[off]
	}
	return stripped, mapBack
}

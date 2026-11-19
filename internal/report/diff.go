package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// DiffNewFinding is a finding present in the current scan that was not present
// in the baseline scan. TestedInBaseline records whether the baseline actually
// assessed that technique (false means it is newly covered, not necessarily a
// newly introduced regression).
type DiffNewFinding struct {
	Finding          Finding `json:"finding"`
	TestedInBaseline bool    `json:"tested_in_baseline"`
}

// DiffResult is an honest comparison between a baseline scan and a current scan.
//
// A baseline finding is placed in Fixed ONLY when its technique was actually
// assessed in the current scan (present in current.Options.TechniqueIDs and
// absent from current.NoAnswer and current.Unsupported). Findings whose
// techniques were omitted, unanswered, or unsupported in the current scan go to
// NotRetested so an incomplete re-run never looks like remediation.
type DiffResult struct {
	BaselineTarget string           `json:"baseline_target"`
	CurrentTarget  string           `json:"current_target"`
	BaselineAt     time.Time        `json:"baseline_finished_at"`
	CurrentAt      time.Time        `json:"current_finished_at"`
	Fixed          []Finding        `json:"fixed,omitempty"`
	StillOpen      []Finding        `json:"still_open,omitempty"`
	New            []DiffNewFinding `json:"new,omitempty"`
	NotRetested    []Finding        `json:"not_retested,omitempty"`
	Caveats        []string         `json:"caveats,omitempty"`
}

// Diff compares baseline against current and classifies every finding into
// Fixed, StillOpen, New, or NotRetested alongside coverage caveats.
func Diff(baseline, current *Scan) DiffResult {
	res := DiffResult{}
	if baseline != nil {
		res.BaselineTarget = baseline.Target
		res.BaselineAt = baseline.FinishedAt
	}
	if current != nil {
		res.CurrentTarget = current.Target
		res.CurrentAt = current.FinishedAt
	}
	if baseline == nil || current == nil {
		res.Caveats = append(res.Caveats, "one or both scans were missing")
		return res
	}

	if baseline.Unreached() {
		res.Caveats = append(res.Caveats, "baseline scan assessed no techniques (unreached)")
	}
	if current.Unreached() {
		res.Caveats = append(res.Caveats, "current scan assessed no techniques (unreached)")
	}
	if baseline.Target != current.Target {
		res.Caveats = append(res.Caveats, fmt.Sprintf("target changed between runs (%q -> %q)", baseline.Target, current.Target))
	}

	baseAssessed := assessedSet(baseline)
	currAssessed := assessedSet(current)

	if !sameStringSet(baseAssessed, currAssessed) {
		res.Caveats = append(res.Caveats, fmt.Sprintf(
			"assessed technique sets differ (baseline assessed %d, current assessed %d)",
			len(baseAssessed), len(currAssessed),
		))
	}

	// Count occurrences per TechniqueID to choose matching granularity:
	// active scans emit at most one finding per TechniqueID (so we match by
	// TechniqueID even if LLM wording varies slightly across runs), while
	// passive surface scans can emit multiple findings under one rule ID
	// (disambiguated by Fingerprint).
	baseCounts := countByTech(baseline.Findings)
	currCounts := countByTech(current.Findings)

	keyFor := func(f Finding) string {
		if baseCounts[f.TechniqueID] > 1 || currCounts[f.TechniqueID] > 1 {
			return f.TechniqueID + "\x00" + f.Fingerprint
		}
		return f.TechniqueID
	}

	baseMap := map[string]Finding{}
	for _, f := range baseline.Findings {
		baseMap[keyFor(f)] = f
	}
	currMap := map[string]Finding{}
	for _, f := range current.Findings {
		currMap[keyFor(f)] = f
	}

	for _, bf := range baseline.Findings {
		k := keyFor(bf)
		if cf, still := currMap[k]; still {
			res.StillOpen = append(res.StillOpen, cf)
			continue
		}
		if wasRetested(bf, current, currAssessed) {
			res.Fixed = append(res.Fixed, bf)
		} else {
			res.NotRetested = append(res.NotRetested, bf)
		}
	}

	for _, cf := range current.Findings {
		k := keyFor(cf)
		if _, existed := baseMap[k]; existed {
			continue
		}
		res.New = append(res.New, DiffNewFinding{
			Finding:          cf,
			TestedInBaseline: wasRetested(cf, baseline, baseAssessed),
		})
	}

	sortFindings(res.Fixed)
	sortFindings(res.StillOpen)
	sortFindings(res.NotRetested)
	sort.SliceStable(res.New, func(i, j int) bool {
		return res.New[i].Finding.TechniqueID < res.New[j].Finding.TechniqueID
	})

	if len(res.NotRetested) > 0 {
		res.Caveats = append(res.Caveats, fmt.Sprintf(
			"%d baseline finding(s) were not retested in the current run and cannot be counted as fixed",
			len(res.NotRetested),
		))
	}

	return res
}

// ExitCode returns 1 if current introduced any new finding, 0 otherwise.
func (d DiffResult) ExitCode() int {
	if len(d.New) > 0 {
		return 1
	}
	return 0
}

func assessedSet(s *Scan) map[string]bool {
	out := map[string]bool{}
	if s == nil {
		return out
	}
	for _, id := range s.Options.TechniqueIDs {
		out[id] = true
	}
	for _, id := range s.NoAnswer {
		delete(out, id)
	}
	for _, u := range s.Unsupported {
		delete(out, u.TechniqueID)
	}
	return out
}

func wasRetested(f Finding, s *Scan, assessed map[string]bool) bool {
	if assessed[f.TechniqueID] {
		return true
	}
	// Shared detectors (recitation, declined-then-produced) are not in
	// Options.TechniqueIDs; they are retested if at least one of the techniques
	// that drew them (or any technique, when DrawnBy is empty) was assessed AND
	// the corresponding shared detector was enabled.
	if len(f.DrawnBy) > 0 && s != nil && len(assessed) > 0 {
		if f.TechniqueID == "probe.llm07.rule-recitation" && s.Options.RecitationThreshold == 0 {
			return false
		}
		if f.TechniqueID == "probe.llm01.declined-then-produced" && !s.Options.DeclinedProduced {
			return false
		}
		for _, drawer := range f.DrawnBy {
			if assessed[drawer] {
				return true
			}
		}
	}
	return false
}

func countByTech(fs []Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.TechniqueID]++
	}
	return m
}

func sameStringSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// WriteDiffJSON writes the diff result as indented JSON.
func WriteDiffJSON(w io.Writer, d DiffResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(d); err != nil {
		return fmt.Errorf("write diff JSON: %w", err)
	}
	return nil
}

// WriteDiffText writes a concise terminal diff summary.
func WriteDiffText(w io.Writer, d DiffResult) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Diff: %s -> %s\n", d.BaselineTarget, d.CurrentTarget)
	fmt.Fprintf(&b, "Summary: %d new, %d still open, %d fixed, %d not retested\n",
		len(d.New), len(d.StillOpen), len(d.Fixed), len(d.NotRetested))

	if len(d.Caveats) > 0 {
		b.WriteString("\nCaveats:\n")
		for _, c := range d.Caveats {
			fmt.Fprintf(&b, "  ! %s\n", c)
		}
	}
	if len(d.New) > 0 {
		b.WriteString("\nNew findings:\n")
		for _, nf := range d.New {
			origin := "regression"
			if !nf.TestedInBaseline {
				origin = "not tested in baseline"
			}
			fmt.Fprintf(&b, "  + [%-8s] %s (%s) — %s\n",
				strings.ToUpper(string(nf.Finding.Severity)), nf.Finding.TechniqueID, origin, nf.Finding.Title)
		}
	}
	if len(d.StillOpen) > 0 {
		b.WriteString("\nStill open:\n")
		for _, f := range d.StillOpen {
			fmt.Fprintf(&b, "  = [%-8s] %s — %s\n",
				strings.ToUpper(string(f.Severity)), f.TechniqueID, f.Title)
		}
	}
	if len(d.Fixed) > 0 {
		b.WriteString("\nFixed (retested and no longer reproducing):\n")
		for _, f := range d.Fixed {
			fmt.Fprintf(&b, "  - [%-8s] %s — %s\n",
				strings.ToUpper(string(f.Severity)), f.TechniqueID, f.Title)
		}
	}
	if len(d.NotRetested) > 0 {
		b.WriteString("\nNot retested (cannot be counted as fixed):\n")
		for _, f := range d.NotRetested {
			fmt.Fprintf(&b, "  ? [%-8s] %s — %s\n",
				strings.ToUpper(string(f.Severity)), f.TechniqueID, f.Title)
		}
	}

	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write diff text: %w", err)
	}
	return nil
}

// WriteDiffMarkdown writes a Markdown scan-to-scan diff report.
func WriteDiffMarkdown(w io.Writer, d DiffResult) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Scan diff — %s\n\n", d.CurrentTarget)
	fmt.Fprintf(&b, "| Bucket | Count |\n|---|---|\n")
	fmt.Fprintf(&b, "| New | %d |\n", len(d.New))
	fmt.Fprintf(&b, "| Still open | %d |\n", len(d.StillOpen))
	fmt.Fprintf(&b, "| Fixed | %d |\n", len(d.Fixed))
	fmt.Fprintf(&b, "| Not retested | %d |\n\n", len(d.NotRetested))

	if len(d.Caveats) > 0 {
		b.WriteString("> **Caveats**\n>\n")
		for _, c := range d.Caveats {
			fmt.Fprintf(&b, "> - %s\n", c)
		}
		b.WriteString("\n")
	}

	if len(d.New) > 0 {
		b.WriteString("## New findings\n\n")
		for _, nf := range d.New {
			note := "tested in baseline"
			if !nf.TestedInBaseline {
				note = "not tested in baseline"
			}
			fmt.Fprintf(&b, "- **%s** `%s` — %s (%s)\n",
				title(nf.Finding.Severity), nf.Finding.TechniqueID, nf.Finding.Title, note)
		}
		b.WriteString("\n")
	}
	if len(d.StillOpen) > 0 {
		b.WriteString("## Still open\n\n")
		for _, f := range d.StillOpen {
			fmt.Fprintf(&b, "- **%s** `%s` — %s\n", title(f.Severity), f.TechniqueID, f.Title)
		}
		b.WriteString("\n")
	}
	if len(d.Fixed) > 0 {
		b.WriteString("## Fixed\n\n")
		for _, f := range d.Fixed {
			fmt.Fprintf(&b, "- **%s** `%s` — %s\n", title(f.Severity), f.TechniqueID, f.Title)
		}
		b.WriteString("\n")
	}
	if len(d.NotRetested) > 0 {
		b.WriteString("## Not retested\n\n")
		for _, f := range d.NotRetested {
			fmt.Fprintf(&b, "- **%s** `%s` — %s\n", title(f.Severity), f.TechniqueID, f.Title)
		}
		b.WriteString("\n")
	}

	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write diff markdown: %w", err)
	}
	return nil
}

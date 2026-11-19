package report

import (
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/radeksixi/sixi-scanner/internal/tech"
)

type htmlSeverityCount struct {
	Level string
	Label string
	Count int
}

type htmlFinding struct {
	Index            int
	Finding          Finding
	SeverityLabel    string
	SeverityClass    string
	ConfidenceText   string
	ReproductionNote string
	DrawnByText      string
	MarkersText      string
	NegatedText      string
}

type htmlView struct {
	Tool           string
	Version        string
	Target         string
	FinishedAt     string
	Attempts       int
	Redacted       bool
	TargetNotes    []string
	SelectedCount  int
	AssessedCount  int
	UntestedCount  int
	NoAnswer       []string
	Unsupported    []Unsupported
	Undecided      []Undecided
	SeverityCounts []htmlSeverityCount
	Findings       []htmlFinding
	FirstTech      string
}

var htmlReportTmpl = template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan report — {{.Target}}</title>
<style>
  :root {
    --bg: #f8fafc; --surface: #ffffff; --border: #e2e8f0;
    --text: #0f172a; --muted: #475569; --code-bg: #0f172a; --code-fg: #f1f5f9;
    --crit: #991b1b; --crit-bg: #fee2e2;
    --high: #9a3412; --high-bg: #ffedd5;
    --med: #854d0e; --med-bg: #fef9c3;
    --low: #1e40af; --low-bg: #dbeafe;
    --info: #334155; --info-bg: #e2e8f0;
    --warn-bg: #fffbeb; --warn-border: #f59e0b;
  }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.55; }
  .wrap { max-width: 980px; margin: 0 auto; padding: 28px 20px 64px; }
  header { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 20px 24px; margin-bottom: 20px; }
  h1 { margin: 0 0 8px; font-size: 1.45rem; word-break: break-word; }
  h2 { margin: 28px 0 12px; font-size: 1.15rem; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
  h3 { margin: 0 0 8px; font-size: 1.05rem; }
  .meta { color: var(--muted); font-size: 0.9rem; display: flex; flex-wrap: wrap; gap: 14px; }
  .note-box { background: var(--warn-bg); border: 1px solid var(--warn-border); border-radius: 8px; padding: 12px 16px; margin: 16px 0; }
  .note-box ul { margin: 6px 0 0; padding-left: 20px; }
  .summary-grid { display: flex; flex-wrap: wrap; gap: 10px; margin: 12px 0; }
  .stat { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; min-width: 110px; }
  .stat .num { font-size: 1.4rem; font-weight: 700; display: block; }
  .stat .lbl { font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; margin-bottom: 16px; }
  .card-head { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin-bottom: 10px; }
  .badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 0.78rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.03em; }
  .sev-critical { color: var(--crit); background: var(--crit-bg); }
  .sev-high { color: var(--high); background: var(--high-bg); }
  .sev-medium { color: var(--med); background: var(--med-bg); }
  .sev-low { color: var(--low); background: var(--low-bg); }
  .sev-info { color: var(--info); background: var(--info-bg); }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 0.78rem; background: #f1f5f9; color: var(--muted); border: 1px solid var(--border); }
  .kv { width: 100%; border-collapse: collapse; margin: 10px 0 14px; font-size: 0.9rem; }
  .kv th { text-align: left; color: var(--muted); width: 160px; padding: 4px 8px 4px 0; vertical-align: top; font-weight: 600; }
  .kv td { padding: 4px 0; vertical-align: top; }
  pre { background: var(--code-bg); color: var(--code-fg); padding: 12px 14px; border-radius: 8px; overflow-x: auto; font-size: 0.84rem; line-height: 1.45; white-space: pre-wrap; word-break: break-word; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.88em; }
  .section-lbl { font-weight: 600; font-size: 0.88rem; color: var(--muted); margin: 12px 0 4px; }
  footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.88rem; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Scan report — {{.Target}}</h1>
    <div class="meta">
      <span><strong>Tool:</strong> {{.Tool}} {{.Version}}</span>
      <span><strong>Finished:</strong> {{.FinishedAt}}</span>
      <span><strong>Attempts:</strong> {{.Attempts}}</span>
      {{if .Redacted}}<span class="pill">Evidence redacted</span>{{end}}
    </div>
  </header>

  {{if .TargetNotes}}
  <div class="note-box">
    <strong>Scan-affecting settings</strong>
    <ul>
      {{range .TargetNotes}}<li>{{.}}</li>{{end}}
    </ul>
  </div>
  {{end}}

  <h2>Summary</h2>
  {{if not .Findings}}
  <div class="card">
    {{if eq .UntestedCount 0}}
    <p>No findings. {{.Attempts}} attempts across {{.SelectedCount}} techniques found no confirmed break.</p>
    {{else}}
    <p>No findings. {{.Attempts}} attempts across {{.AssessedCount}} of the {{.SelectedCount}} selected techniques found no confirmed break. <strong>{{.UntestedCount}} were not tested</strong> and are listed below; this result says nothing about them.</p>
    {{end}}
    <p>A clean report is evidence about the techniques that were run, not a statement that the agent is secure. It does not cover techniques this tool does not implement, and it does not cover attacks that need a judgement no string match can make.</p>
  </div>
  {{else}}
  <div class="summary-grid">
    {{range .SeverityCounts}}
    <div class="stat">
      <span class="num">{{.Count}}</span>
      <span class="lbl">{{.Label}}</span>
    </div>
    {{end}}
  </div>
  {{end}}

  {{if gt .UntestedCount 0}}
  <h2>Not tested</h2>
  <div class="card">
    <p>{{.UntestedCount}} of the {{.SelectedCount}} selected techniques were not assessed. A technique listed here did not pass; it was not run.</p>
    {{if .NoAnswer}}
    <div class="section-lbl">No answer from the target</div>
    <ul>{{range .NoAnswer}}<li><code>{{.}}</code></li>{{end}}</ul>
    {{end}}
    {{if .Unsupported}}
    <div class="section-lbl">Not runnable against this target</div>
    <ul>{{range .Unsupported}}<li><code>{{.TechniqueID}}</code> — {{.Reason}}</li>{{end}}</ul>
    {{end}}
  </div>
  {{end}}

  {{if .Undecided}}
  <h2>Could not be decided</h2>
  <div class="card">
    <p>These techniques got an answer that this scan had no way to judge. They are not findings, and they did not pass.</p>
    <ul>{{range .Undecided}}<li><code>{{.TechniqueID}}</code> — {{.Reason}}</li>{{end}}</ul>
  </div>
  {{end}}

  {{if .Findings}}
  <h2>Findings ({{len .Findings}})</h2>
  {{range .Findings}}
  <article class="card">
    <div class="card-head">
      <span class="badge sev-{{.SeverityClass}}">{{.SeverityLabel}}</span>
      <h3>{{.Index}}. {{.Finding.Title}}</h3>
      {{if .Finding.EvidenceBasis}}<span class="pill">evidence: {{.Finding.EvidenceBasis}}</span>{{end}}
      {{if .Finding.NarrationOnly}}<span class="pill">narration only</span>{{end}}
      {{if .ReproductionNote}}<span class="pill">{{.ReproductionNote}}</span>{{end}}
    </div>
    <table class="kv">
      <tr><th>Category</th><td>{{.Finding.Category}}</td></tr>
      <tr><th>Confidence</th><td>{{.ConfidenceText}}</td></tr>
      <tr><th>Technique</th><td><code>{{.Finding.TechniqueID}}</code></td></tr>
      <tr><th>Fingerprint</th><td><code>{{.Finding.Fingerprint}}</code></td></tr>
      {{if gt (len .Finding.Rounds) 1}}<tr><th>Reproduced in</th><td>{{len .Finding.Rounds}} rounds</td></tr>{{end}}
      {{if .DrawnByText}}<tr><th>Drawn by</th><td><code>{{.DrawnByText}}</code></td></tr>{{end}}
    </table>
    {{if .Finding.Description}}<p>{{.Finding.Description}}</p>{{end}}
    <div class="section-lbl">Why this was judged a finding</div>
    <p>{{.Finding.Evidence.Reason}}</p>
    <div class="section-lbl">Prompt sent</div>
    <pre>{{.Finding.Evidence.Prompt}}</pre>
    <div class="section-lbl">Reply received</div>
    <pre>{{.Finding.Evidence.Response}}</pre>
    {{if .MarkersText}}<p><strong>Matched markers:</strong> <code>{{.MarkersText}}</code></p>{{end}}
    {{if .NegatedText}}<p><strong>Discounted as mentions inside a denial:</strong> <code>{{.NegatedText}}</code></p>{{end}}
    {{if .Finding.Remediation}}
    <div class="section-lbl">Remediation</div>
    <p>{{.Finding.Remediation}}</p>
    {{end}}
  </article>
  {{end}}
  {{end}}

  <footer>
    <h3>What this report is not</h3>
    <p>Generated by {{.Tool}} {{.Version}}. Every finding above is a reproducible exchange against the endpoint named at the top, and every one can be re-run with <code>--only {{.FirstTech}}</code>. Nothing here is a certification, an attestation, or a statement of compliance, and no output of this tool says the words <em>compliant</em>, <em>certified</em> or <em>guaranteed</em>.</p>
  </footer>
</div>
</body>
</html>
`))

// WriteHTML writes the scan as a self-contained, auto-escaped HTML report with
// no external network assets and no compliance or certification grading.
func WriteHTML(w io.Writer, s *Scan) error {
	s.Summarise()

	counts := s.CountBySeverity()
	var sevCounts []htmlSeverityCount
	for _, sev := range []tech.Severity{
		tech.SeverityCritical, tech.SeverityHigh,
		tech.SeverityMedium, tech.SeverityLow, tech.SeverityInfo,
	} {
		if counts[sev] > 0 {
			sevCounts = append(sevCounts, htmlSeverityCount{
				Level: string(sev),
				Label: title(sev),
				Count: counts[sev],
			})
		}
	}

	findings := make([]htmlFinding, 0, len(s.Findings))
	for i, f := range s.Findings {
		sev := f.Severity
		if sev == "" {
			sev = tech.SeverityInfo
		}
		findings = append(findings, htmlFinding{
			Index:            i + 1,
			Finding:          f,
			SeverityLabel:    title(sev),
			SeverityClass:    string(sev),
			ConfidenceText:   fmt.Sprintf("%.2f", f.Confidence),
			ReproductionNote: ReproductionNote(f),
			DrawnByText:      strings.Join(f.DrawnBy, ", "),
			MarkersText:      strings.Join(f.Evidence.Markers, ", "),
			NegatedText:      strings.Join(f.Evidence.Negated, ", "),
		})
	}

	view := htmlView{
		Tool:           s.Tool,
		Version:        s.Version,
		Target:         s.Target,
		FinishedAt:     s.FinishedAt.Format(time.RFC3339),
		Attempts:       s.Attempts,
		Redacted:       s.Options.Redacted,
		TargetNotes:    s.TargetNotes,
		SelectedCount:  len(s.Options.TechniqueIDs),
		AssessedCount:  s.Assessed(),
		UntestedCount:  len(s.NoAnswer) + len(s.Unsupported),
		NoAnswer:       s.NoAnswer,
		Unsupported:    s.Unsupported,
		Undecided:      s.Undecided,
		SeverityCounts: sevCounts,
		Findings:       findings,
		FirstTech:      firstOrNone(s.Options.TechniqueIDs),
	}

	if err := htmlReportTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("write HTML: %w", err)
	}
	return nil
}

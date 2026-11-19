package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/radeksixi/sixi-scanner/internal/tech"
)

func TestRedactTextOrderedAndScanPreservesFingerprint(t *testing.T) {
	raw := "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c " +
		"db=postgres://admin:supersecret@10.0.0.5:5432/prod " +
		"openai=sk-live-1234567890abcdef1234 " +
		"aws=AKIAIOSFODNN7REALKEY " +
		"email=anna.keller@customer.example " +
		"card=4111-2222-3333-4444"

	got := RedactText(raw)
	for _, secret := range []string{
		"eyJhbGciOiJIUzI1NiJ9", "supersecret", "sk-live-1234567890",
		"AKIAIOSFODNN7REALKEY", "anna.keller@customer.example", "10.0.0.5", "4111-2222-3333-4444",
	} {
		if strings.Contains(got, secret) {
			t.Errorf("secret %q survived redaction in %q", secret, got)
		}
	}
	for _, tok := range []string{"[REDACTED_JWT]", "[REDACTED_SECRET]", "[REDACTED_EMAIL]", "[REDACTED_IP]", "[REDACTED_NUMBER]"} {
		if !strings.Contains(got, tok) {
			t.Errorf("expected placeholder %s in %q", tok, got)
		}
	}

	s := fixture()
	s.Findings[0].Evidence.Response = "API key: sk-live-9f8e7d6c5b4a3210fedc for anna.keller@customer.example"
	s.Findings[0].Fingerprint = Fingerprint(s.Findings[0])
	origFP := s.Findings[0].Fingerprint

	s.Redact()
	if !s.Options.Redacted {
		t.Error("expected Options.Redacted = true")
	}
	if s.Findings[0].Fingerprint != origFP {
		t.Errorf("Redact changed fingerprint: %q -> %q", origFP, s.Findings[0].Fingerprint)
	}
	if strings.Contains(s.Findings[0].Evidence.Response, "sk-live-") {
		t.Errorf("secret survived Scan.Redact: %q", s.Findings[0].Evidence.Response)
	}
}

func TestSARIFUpgrades(t *testing.T) {
	s := fixture()
	s.Findings[0].Evidence.Response = "Secret token sk-live-9f8e7d6c5b4a3210fedc leaked"
	s.Findings[0].EvidenceBasis = "trace"
	s.Findings[0].Reproduced = 3
	s.Findings[0].Trials = 3

	var buf strings.Builder
	if err := WriteSARIF(&buf, s); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if strings.Contains(out, "sk-live-9f8e7d6c5b4a3210fedc") {
		t.Error("SARIF snippet leaked raw API key without redaction")
	}
	if !strings.Contains(out, `"security-severity": "7.0"`) {
		t.Errorf("SARIF missing security-severity 7.0:\n%s", out)
	}
	if !strings.Contains(out, `"automationDetails"`) {
		t.Errorf("SARIF missing automationDetails:\n%s", out)
	}
	if !strings.Contains(out, `"markdown":`) {
		t.Errorf("SARIF rule help missing markdown field:\n%s", out)
	}
	if !strings.Contains(out, `"ruleIndex":`) {
		t.Errorf("SARIF result missing ruleIndex:\n%s", out)
	}
	if !strings.Contains(out, `"evidence_basis": "trace"`) {
		t.Errorf("SARIF result properties missing evidence_basis:\n%s", out)
	}
	if !strings.Contains(out, "reproduced 3/3 trials") {
		t.Errorf("SARIF missing reproduction note:\n%s", out)
	}
}

func TestWriteHTMLAutoEscapesAndIncludesDisclaimer(t *testing.T) {
	s := fixture()
	s.Target = `http://agent.example/<script>alert("t")</script>`
	s.Findings[0].Evidence.Prompt = `<img src=x onerror=alert(1)>`
	s.Findings[0].Evidence.Response = `<script>alert('xss')</script>`
	s.Findings[0].EvidenceBasis = "trace"
	s.Findings[0].NarrationOnly = true
	s.Findings[0].Reproduced = 2
	s.Findings[0].Trials = 3
	s.NoAnswer = []string{"probe.llm01.timeout"}
	s.Undecided = []Undecided{{TechniqueID: "probe.llm09.false-action-claim", Reason: "no tool trace"}}

	var buf strings.Builder
	if err := WriteHTML(&buf, s); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// Active XSS tags must be HTML-escaped.
	if strings.Contains(out, "<script>alert(") || strings.Contains(out, "<img src=x onerror=") {
		t.Fatalf("HTML report failed to escape untrusted markup:\n%s", out)
	}
	for _, want := range []string{
		"&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
		"Nothing here is a certification",
		"no output of this tool says the words",
		"Not tested",
		"Could not be decided",
		"reproduced 2/3 trials",
		"narration only",
		"evidence: trace",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
}

func TestDiffHonestBucketsAndRenderers(t *testing.T) {
	at := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	mkDef := func(id, title string, sev tech.Severity) tech.Definition {
		return tech.Definition{ID: id, Title: title, Severity: sev, Category: "LLM01"}
	}
	fFixed := NewFinding(mkDef("probe.llm01.fixed", "Fixed", tech.SeverityHigh), Evidence{Response: "leaked"}, 0.8, 1, at)
	fOpen := NewFinding(mkDef("probe.llm01.open", "Open", tech.SeverityCritical), Evidence{Response: "still leaked"}, 0.9, 1, at)
	fSkipped := NewFinding(mkDef("probe.llm01.skipped", "Skipped", tech.SeverityMedium), Evidence{Response: "leaked before"}, 0.7, 1, at)
	fNewReg := NewFinding(mkDef("probe.llm02.regression", "Regression", tech.SeverityHigh), Evidence{Response: "new leak"}, 0.85, 1, at.Add(time.Hour))
	fNewCov := NewFinding(mkDef("probe.llm05.new-probe", "New coverage", tech.SeverityLow), Evidence{Response: "new probe"}, 0.6, 1, at.Add(time.Hour))

	base := &Scan{
		Target:     "http://agent.example",
		FinishedAt: at,
		Options: Options{
			TechniqueIDs: []string{"probe.llm01.fixed", "probe.llm01.open", "probe.llm01.skipped", "probe.llm02.regression"},
		},
		Findings: []Finding{fFixed, fOpen, fSkipped},
	}
	curr := &Scan{
		Target:     "http://agent.example",
		FinishedAt: at.Add(time.Hour),
		Options: Options{
			TechniqueIDs: []string{"probe.llm01.fixed", "probe.llm01.open", "probe.llm01.skipped", "probe.llm02.regression", "probe.llm05.new-probe"},
		},
		NoAnswer: []string{"probe.llm01.skipped"}, // timed out -> must NOT be counted as Fixed!
		Findings: []Finding{fOpen, fNewReg, fNewCov},
	}

	d := Diff(base, curr)
	if len(d.Fixed) != 1 || d.Fixed[0].TechniqueID != "probe.llm01.fixed" {
		t.Errorf("Fixed = %+v, want [probe.llm01.fixed]", d.Fixed)
	}
	if len(d.StillOpen) != 1 || d.StillOpen[0].TechniqueID != "probe.llm01.open" {
		t.Errorf("StillOpen = %+v, want [probe.llm01.open]", d.StillOpen)
	}
	if len(d.NotRetested) != 1 || d.NotRetested[0].TechniqueID != "probe.llm01.skipped" {
		t.Errorf("NotRetested = %+v, want [probe.llm01.skipped]", d.NotRetested)
	}
	if len(d.New) != 2 {
		t.Fatalf("New = %d, want 2", len(d.New))
	}
	testedMap := map[string]bool{}
	for _, nf := range d.New {
		testedMap[nf.Finding.TechniqueID] = nf.TestedInBaseline
	}
	if !testedMap["probe.llm02.regression"] {
		t.Error("expected probe.llm02.regression to have TestedInBaseline=true")
	}
	if testedMap["probe.llm05.new-probe"] {
		t.Error("expected probe.llm05.new-probe to have TestedInBaseline=false")
	}
	if d.ExitCode() != 1 {
		t.Errorf("ExitCode = %d, want 1 when new findings exist", d.ExitCode())
	}
	if len(d.Caveats) == 0 {
		t.Error("expected caveats for differing technique coverage and not-retested finding")
	}

	// Renderers all succeed and round-trip JSON.
	var textBuf, mdBuf, jsonBuf strings.Builder
	if err := WriteDiffText(&textBuf, d); err != nil {
		t.Fatal(err)
	}
	if err := WriteDiffMarkdown(&mdBuf, d); err != nil {
		t.Fatal(err)
	}
	if err := WriteDiffJSON(&jsonBuf, d); err != nil {
		t.Fatal(err)
	}
	var parsed DiffResult
	if err := json.Unmarshal([]byte(jsonBuf.String()), &parsed); err != nil {
		t.Fatalf("diff JSON invalid: %v", err)
	}
	if !strings.Contains(textBuf.String(), "Not retested") || !strings.Contains(mdBuf.String(), "## Fixed") {
		t.Error("diff text/markdown missing expected sections")
	}
}

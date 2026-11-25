package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/radeksixi/sixi-scanner/internal/adaptive"
	"github.com/radeksixi/sixi-scanner/internal/confirm"
	"github.com/radeksixi/sixi-scanner/internal/engine"
	"github.com/radeksixi/sixi-scanner/internal/judge"
	"github.com/radeksixi/sixi-scanner/internal/policy"
	"github.com/radeksixi/sixi-scanner/internal/report"
	"github.com/radeksixi/sixi-scanner/internal/target"
	"github.com/radeksixi/sixi-scanner/internal/tech"
	"github.com/radeksixi/sixi-scanner/internal/tech/baseline"
)

func cmdScan(args []string, stdout, stderr io.Writer) result {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)

	var (
		url       = fs.String("url", "", "endpoint to scan (required unless --target echo)")
		connector = fs.String("target", "openai", "transport: openai, responses, azure, gemini, anthropic, json, chat, mcp, a2a, webform, echo")
		headers   = headerFlag{}

		model      = fs.String("model", "", "model field for provider transports (openai, responses, azure, gemini, anthropic)")
		stateful   = fs.Bool("stateful", false, "maintain client-side conversation history per session so multi-turn sequences run on provider transports (openai, azure, gemini, anthropic)")
		bodyTpl    = fs.String("body", "", "request body template for the json transport; {{prompt}}, {{json}}, {{session}} and {{session_json}} are substituted")
		replyPath  = fs.String("reply-path", "", "dotted path to the reply in the json transport's response")
		tracePath  = fs.String("trace-path", "", "dotted path to the tool-call array in json or chat transport responses")
		mcpTool    = fs.String("tool", "", "MCP tool name for --target mcp (auto-discovers first text-taking tool when empty)")
		formField  = fs.String("field", "", "form field name for the webform transport")
		formSelect = fs.String("reply-selector", "", "open|close markers delimiting the reply in the page, as \"<div class=reply>|<div class=input\"")

		pack        = fs.String("pack", "agent", "probe pack: agent (50 agentic probes), safety (6 content-safety boundary probes), all (56 probes)")
		only        = fs.String("only", "", "comma-separated technique IDs to run; default is all")
		exclude     = fs.String("exclude", "", "comma-separated technique IDs to skip")
		tag         = fs.String("tag", "", "comma-separated tags; only techniques carrying all of them run")
		minSeverity = fs.String("min-severity", "", "skip findings below this severity: info, low, medium, high, critical")

		// Optional adaptive domain-attack & multi-turn Crescendo stage: off by default.
		attackerURL    = fs.String("attacker-url", "", "optional OpenAI-compatible LLM endpoint to generate polite domain scenarios from --context and run adaptive multi-turn Crescendo backtracking")
		attackerModel  = fs.String("attacker-model", "", "model name for --attacker-url")
		attackerKey    = fs.String("attacker-key", os.Getenv("SIXI_ATTACKER_API_KEY"), "bearer token for --attacker-url (or set SIXI_ATTACKER_API_KEY)")
		attackerBudget = fs.Int("attacker-budget", 8, "max domain-tailored adaptive scenarios generated when --attacker-url is set")
		adaptiveTurns  = fs.Int("adaptive-turns", 3, "max conversation turns per adaptive scenario (Crescendo backtracking on session-capable targets)")
		adaptiveOnly   = fs.Bool("adaptive-only", false, "run only adaptive scenarios from --attacker-url, skipping static baseline probes")

		rounds      = fs.Int("rounds", 1, "how many times to walk the whole technique set")
		attempts    = fs.Int("attempts", 3, "max payload variants per technique per round")
		concurrency = fs.Int("concurrency", 4, "techniques in flight at once")
		timeout     = fs.Duration("timeout", 60*time.Second, "per-request timeout")
		minConf     = fs.Float64("min-confidence", 0, "discard breaks scoring below this")
		seed        = fs.String("seed", "", "prompt sent before every probe, to start each conversation from the same state")

		reciteTh = fs.Int("recitation-threshold", judge.DefaultRecitationThreshold,
			"lines stating a constraint on the agent itself before the reply counts as reciting its "+
				"operating rules; 0 disables the test. See docs/recitation.md")
		declinedProd = fs.Bool("declined-produced", true,
			"flag replies that decline a request and then emit a code, SQL, config or action artefact anyway")
		reproduce = fs.Int("reproduce", 0,
			"re-run each finding's breaking payload this many extra times to measure reproducibility (k/n)")

		// The optional confirmation stage: off unless an endpoint is named.
		confirmURL    = fs.String("confirm-url", "", "OpenAI-compatible or laya-as-judge (/v1/judge, /v1/judged-decision, /v1/decisions) endpoint to verify candidate breaks; empty disables the stage")
		confirmModel  = fs.String("confirm-model", "", "model name to ask at --confirm-url (optional when --confirm-url points at laya-as-judge)")
		confirmKey    = fs.String("confirm-key", os.Getenv("SIXI_CONFIRM_API_KEY"), "bearer token for --confirm-url (or set SIXI_CONFIRM_API_KEY)")
		confirmFloor  = fs.String("confirm-min-severity", "medium", "lowest severity an answer may carry and still keep a finding: none, low, medium, high, critical")
		confirmBudget = fs.Int("confirm-budget", 200,
			"how many candidates the stage may ask about in one scan; 0 means unlimited")
		contextPath = fs.String("context", "",
			"JSON file describing the agent: {\"purpose\": \"...\", \"policy\": {...}}. \"purpose\" is required by --confirm-url; \"policy\" enables deterministic tool-call checks on observed traces")

		insecure   = fs.Bool("insecure", false, "skip TLS verification (self-signed staging endpoints)")
		redact     = fs.Bool("redact", false, "scrub secrets, tokens, emails, IPs and long account numbers from finding evidence before writing reports")
		logJSONL   = fs.String("log-jsonl", "", "write one JSON line per attempt (prompt, reply, tool calls, latency, mechanism, verdict) for observability")
		quiet      = fs.Bool("quiet", false, "only print the report to stdout")
		outPath    = fs.String("out", "", "also write the report to this file")
		exportLaya = fs.String("export-laya", "", "export findings as deterministic regression guardrail rules JSON for laya-as-judge (load_sixi_scanner_rules / --rules-file)")
		format     = fs.String("format", "text", "stdout format: text, json, sarif, markdown, html")

		extraTimeout = fs.Duration("overall-timeout", 0, "abort the whole scan after this long; 0 means no limit")
	)
	fs.Var(headers, "header", "extra header as \"Name: value\"; repeat the flag for more than one")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sixi-scanner scan --url <endpoint> [flags]

Sends probe prompts to an endpoint and reports what broke. Only scan endpoints
you are authorised to test.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprint(os.Stderr, `
Examples:
  # OpenAI-compatible chat endpoint
  sixi-scanner scan --url https://agent.example/v1/chat/completions

  # Bespoke internal agent, no OpenAI shape
  sixi-scanner scan --target json --url https://internal/api/ask \
    --body '{"question":{{json}},"session":"s1"}' --reply-path answer.text

  # Website chatbot with no API
  sixi-scanner scan --target webform --url https://site.example/chat --field message

  # See the shape of a report without touching the network
  sixi-scanner scan --target echo --format markdown

  # Gate a pull request
  sixi-scanner scan --url "$AGENT_URL" --format sarif --out sixi.sarif
`)
	}
	if err := fs.Parse(args); err != nil {
		// Asking for help is not a failure. The flag package has already printed the usage.
		if errors.Is(err, flag.ErrHelp) {
			return result{code: exitOK}
		}
		return result{code: exitUsage, err: err}
	}

	// Validate before touching the network, so a typo costs nothing. The format is checked here
	// rather than when the report is written: by then the scan has run, and a mistyped --format
	// threw its result away.
	if err := checkFormat(*format); err != nil {
		return result{code: exitUsage, err: err}
	}
	if *reproduce < 0 {
		return result{code: exitUsage, err: fmt.Errorf("--reproduce must be >= 0, got %d", *reproduce)}
	}
	if *adaptiveOnly && strings.TrimSpace(*attackerURL) == "" {
		return result{code: exitUsage, err: fmt.Errorf("--adaptive-only requires --attacker-url")}
	}
	if strings.TrimSpace(*attackerURL) != "" {
		if *contextPath == "" {
			return result{code: exitUsage, err: fmt.Errorf("--attacker-url requires --context (purpose and/or wire policy) so generated probes match the target's domain")}
		}
		if *attackerBudget <= 0 {
			return result{code: exitUsage, err: fmt.Errorf("--attacker-budget must be >= 1, got %d", *attackerBudget)}
		}
		if *adaptiveTurns <= 0 {
			return result{code: exitUsage, err: fmt.Errorf("--adaptive-turns must be >= 1, got %d", *adaptiveTurns)}
		}
	}
	cfg := target.Config{
		URL:      *url,
		Timeout:  *timeout,
		Insecure: *insecure,
		Headers:  headers.orNil(),
		Extra:    map[string]string{},
	}
	if *model != "" {
		cfg.Extra["model"] = *model
	}
	if *stateful {
		cfg.Extra["stateful"] = "true"
	}
	if *bodyTpl != "" {
		cfg.Extra["body"] = *bodyTpl
	}
	if *replyPath != "" {
		cfg.Extra["reply-path"] = *replyPath
	}
	if *tracePath != "" {
		cfg.Extra["trace-path"] = *tracePath
	}
	if *mcpTool != "" {
		cfg.Extra["tool"] = *mcpTool
	}
	if *formField != "" {
		cfg.Extra["field"] = *formField
	}
	if *formSelect != "" {
		cfg.Extra["reply-selector"] = *formSelect
	}

	tgt, err := target.New(*connector, cfg)
	if err != nil {
		return result{code: exitUsage, err: err}
	}

	reg, err := selectTechniques(*pack, splitCommaList(*only), splitCommaList(*exclude), splitCommaList(*tag))
	if err != nil {
		return result{code: exitUsage, err: err}
	}

	floor, err := parseFloor(*minSeverity)
	if err != nil {
		return result{code: exitUsage, err: err}
	}
	if floor != "" {
		reg = filterBySeverity(reg, floor)
		if reg.Len() == 0 {
			return result{code: exitUsage, err: fmt.Errorf("no techniques at or above severity %q", floor)}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *extraTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *extraTimeout)
		defer cancel()
	}

	// The confirmation stage is opt-in and needs a policy to grade against, so
	// the two flags are validated together before anything is sent. Failing
	// here costs nothing; failing mid-scan would waste the run.
	scanCfg := engine.Config{
		Target:           tgt,
		Registry:         reg,
		Rounds:           *rounds,
		MaxAttempts:      *attempts,
		Concurrency:      *concurrency,
		Seed:             *seed,
		MinConfidence:    *minConf,
		Recitation:       judge.RecitationThreshold(*reciteTh),
		DeclinedProduced: *declinedProd,
		Reproduce:        *reproduce,
	}

	var tc *targetContext
	if *contextPath != "" {
		var err error
		tc, err = loadContextFile(*contextPath, *confirmURL != "")
		if err != nil {
			return result{code: exitUsage, err: err}
		}
		if tc.Policy != nil && !tc.Policy.Empty() {
			scanCfg.ToolPolicy = tc.Policy
		}
	}

	var stage *confirm.Stage
	if *confirmURL != "" {
		if *contextPath == "" {
			return result{code: exitUsage, err: fmt.Errorf("--confirm-url needs --context: a confirmation " +
				"stage has to know what the agent is for and which data it may show, and guessing that " +
				"would make its verdicts unfalsifiable")}
		}
		effConfirmModel := *confirmModel
		if effConfirmModel == "" {
			if confirm.IsLayaURL(*confirmURL) {
				effConfirmModel = "laya-as-judge"
			} else {
				return result{code: exitUsage, err: fmt.Errorf("--confirm-url needs --confirm-model")}
			}
		}
		// An unrecognised floor ranks as zero, which is "none": a mistyped "hgih" would keep every
		// candidate the model called a violation at any severity. Refused here, before anything
		// is sent, rather than discovered in a report.
		if !confirm.ValidFloor(*confirmFloor) {
			return result{code: exitUsage, err: fmt.Errorf("--confirm-min-severity %q is not a severity; use one of %s",
				*confirmFloor, confirm.FloorNames())}
		}
		stage = confirm.NewStage(confirm.New(*confirmURL, effConfirmModel, *confirmKey, *timeout, *confirmBudget), *confirmFloor)
		scanCfg.Confirm = stage
		scanCfg.Policy = tc.Purpose
	}
	var attemptLog *report.JSONLLogger
	if *logJSONL != "" {
		var err error
		attemptLog, err = report.OpenJSONLLogger(*logJSONL)
		if err != nil {
			return result{code: exitUsage, err: err}
		}
		defer attemptLog.Close()
	}

	var printer func(report.Attempt)
	if !*quiet {
		printer = progressPrinter(stderr)
	}
	if printer != nil || attemptLog != nil {
		scanCfg.OnAttempt = func(a report.Attempt) {
			if printer != nil {
				printer(a)
			}
			if attemptLog != nil {
				attemptLog.Write(a)
			}
		}
	}

	var scan *report.Scan
	if !*adaptiveOnly {
		scan, err = engine.Run(ctx, scanCfg)
		if err != nil {
			if attemptLog != nil {
				_ = attemptLog.Close()
			}
			return result{code: exitUsage, err: err}
		}
	} else {
		now := time.Now().UTC()
		scan = &report.Scan{
			SchemaVersion: report.SchemaVersion,
			Target:        tgt.Describe(),
			StartedAt:     now,
			FinishedAt:    now,
			Options: report.Options{
				Rounds:        1,
				MaxAttempts:   *adaptiveTurns,
				Concurrency:   *concurrency,
				MinConfidence: *minConf,
			},
			Findings: []report.Finding{},
		}
	}

	if strings.TrimSpace(*attackerURL) != "" && ctx.Err() == nil {
		if !*quiet {
			fmt.Fprintf(stderr, "  running adaptive domain + Crescendo pass (%d scenarios x max %d turns via %s)...\n",
				*attackerBudget, *adaptiveTurns, *attackerURL)
		}
		adRes, adErr := adaptive.Run(ctx, adaptive.Config{
			AttackerURL:   *attackerURL,
			AttackerModel: *attackerModel,
			AttackerKey:   *attackerKey,
			Timeout:       *timeout,
			Target:        tgt,
			Purpose:       tc.Purpose,
			ToolPolicy:    scanCfg.ToolPolicy,
			Confirm:       scanCfg.Confirm,
			Seed:          *seed,
			Budget:        *attackerBudget,
			MaxTurns:      *adaptiveTurns,
			Concurrency:   *concurrency,
			OnAttempt:     scanCfg.OnAttempt,
		})
		if adErr != nil {
			if *adaptiveOnly {
				if attemptLog != nil {
					_ = attemptLog.Close()
				}
				return result{code: exitUsage, err: adErr}
			}
			scan.TargetNotes = append(scan.TargetNotes, fmt.Sprintf("Adaptive attacker stage failed: %v", adErr))
		} else {
			scan.FinishedAt = time.Now().UTC()
			scan.Attempts += adRes.TurnsSent
			scan.Findings = append(scan.Findings, adRes.Findings...)
			seenID := map[string]bool{}
			for _, id := range scan.Options.TechniqueIDs {
				seenID[id] = true
			}
			for _, a := range adRes.Attempts {
				if !seenID[a.TechniqueID] {
					seenID[a.TechniqueID] = true
					scan.Options.TechniqueIDs = append(scan.Options.TechniqueIDs, a.TechniqueID)
				}
			}
			scan.TargetNotes = append(scan.TargetNotes, fmt.Sprintf(
				"Adaptive attacker pass ran %d domain scenarios (%d turns, max %d turns/scenario) via %s.",
				adRes.ScenariosGenerated, adRes.TurnsSent, *adaptiveTurns, *attackerURL))
		}
	}

	if attemptLog != nil {
		if cerr := attemptLog.Close(); cerr != nil {
			return result{code: exitUsage, err: fmt.Errorf("flush --log-jsonl: %w", cerr)}
		}
	}
	scan.Tool = toolName
	// The same version the version command prints. The bare variable is "dev" for anyone who
	// installed with `go install`, so their reports could not be tied to a release.
	scan.Version = resolveVersion()
	if *insecure {
		scan.TargetNotes = append(scan.TargetNotes,
			"TLS verification was disabled (--insecure).")
	}
	if stage != nil {
		asked, _, rejected, exhausted := stage.Stats()
		scan.Confirm = &report.Confirmation{
			Model:     stage.Model(),
			Asked:     asked,
			Rejected:  rejected,
			Exhausted: exhausted,
		}
	}

	applyMinSeverity(scan, floor)

	if ctx.Err() != nil {
		scan.TargetNotes = append(scan.TargetNotes,
			"The scan was stopped before every technique had been tried. Coverage is partial.")
	}
	if scan.Unreached() {
		scan.TargetNotes = append(scan.TargetNotes,
			"No technique got an answer from the target. Nothing was assessed; this is not a clean result.")
	} else if scan.Partial() && ctx.Err() == nil {
		scan.TargetNotes = append(scan.TargetNotes, fmt.Sprintf(
			"%d of the %d selected techniques got no answer from the target and were not assessed. Coverage is partial.",
			len(scan.NoAnswer), len(scan.Options.TechniqueIDs)))
	}
	scan.Summarise()
	if *redact {
		scan.Redact()
		scan.TargetNotes = append(scan.TargetNotes,
			"Secrets and PII were redacted from finding evidence (--redact).")
	}

	if err := writeReport(stdout, *format, scan, !*quiet); err != nil {
		return result{code: exitUsage, err: err}
	}
	if *outPath != "" {
		if err := writeFile(*outPath, *format, scan); err != nil {
			return result{code: exitUsage, err: err}
		}
	}
	if *exportLaya != "" {
		if err := writeLayaGuardPackFile(*exportLaya, scan); err != nil {
			return result{code: exitUsage, err: err}
		}
	}

	// A cancelled scan exits 3 rather than 0. A CI job that treats "no findings"
	// as a pass must not read a run that never finished as a pass.
	if ctx.Err() != nil {
		return result{code: exitPartial, err: fmt.Errorf("scan stopped before completion")}
	}
	if len(scan.Findings) > 0 {
		return result{code: exitFindings}
	}
	// No technique got an answer: the target was never reached. Exiting 0 here
	// would let a CI job read a down endpoint as a clean agent.
	if scan.Unreached() {
		return result{code: exitUsage, err: fmt.Errorf("no technique got an answer from %s; nothing was assessed", scan.Target)}
	}
	// Some techniques got an answer and some never did. "Nothing broke" is true of
	// the first group only, so this is the same outcome as an interrupted scan: it
	// did not cover what it was asked to cover, and it must not read as a pass.
	if scan.Partial() {
		return result{code: exitPartial, err: fmt.Errorf(
			"%d of %d techniques got no answer from %s; coverage is partial",
			len(scan.NoAnswer), len(scan.Options.TechniqueIDs), scan.Target)}
	}
	return result{code: exitOK}
}

// selectTechniques loads the chosen pack and applies --only, --exclude and --tag in that order.
func selectTechniques(pack string, only, exclude, tags []string) (*tech.Registry, error) {
	reg, err := baseline.RegistryForPack(pack)
	if err != nil {
		return nil, err
	}

	if len(only) > 0 {
		var err error
		if reg, err = reg.Select(only); err != nil {
			return nil, err
		}
	}
	if len(tags) > 0 {
		reg = reg.SelectMatching(tags)
		if reg.Len() == 0 {
			return nil, fmt.Errorf("no technique carries all of the tags %s", strings.Join(tags, ", "))
		}
	}
	if len(exclude) > 0 {
		keep := make([]string, 0, reg.Len())
		drop := map[string]bool{}
		for _, id := range exclude {
			drop[id] = true
		}
		for _, id := range reg.IDs() {
			if !drop[id] {
				keep = append(keep, id)
			}
		}
		if len(keep) == len(reg.IDs()) {
			return nil, fmt.Errorf("none of %s are in the selected set", strings.Join(exclude, ", "))
		}
		var err error
		if reg, err = reg.Select(keep); err != nil {
			return nil, err
		}
	}
	return reg, nil
}

func parseFloor(s string) (tech.Severity, error) {
	if s == "" {
		return "", nil
	}
	v, ok := tech.ParseSeverity(s)
	if !ok {
		return "", fmt.Errorf("unknown severity %q; use info, low, medium, high or critical", s)
	}
	return v, nil
}

func filterBySeverity(reg *tech.Registry, floor tech.Severity) *tech.Registry {
	out := tech.NewRegistry()
	for _, t := range reg.All() {
		if t.Meta().Severity.AtLeast(floor) {
			out.MustAdd(t)
		}
	}
	return out
}

// applyMinSeverity drops findings below the floor from an already-run scan.
//
// The floor has already been applied to the technique set before anything was
// sent, so in practice this is belt and braces. It stays because the two
// filters are not the same thing: the first decides what to probe, this one
// decides what to publish.
func applyMinSeverity(scan *report.Scan, floor tech.Severity) {
	if floor == "" {
		return
	}
	// Recorded with the other options: a report that lists no low-severity finding reads
	// differently once it says that none were looked for.
	scan.Options.MinSeverity = string(floor)
	kept := scan.Findings[:0]
	for _, f := range scan.Findings {
		if f.Severity.AtLeast(floor) {
			kept = append(kept, f)
		}
	}
	scan.Findings = kept
}

// headerFlag collects --header values across repeats of the flag.
//
// It has to accumulate. As a plain string flag the last --header replaced the ones before it, so
// `--header "Authorization: …" --header "X-Tenant: …"` sent the tenant and dropped the credential,
// and the scan that followed was an unauthenticated one that nobody had asked for.
type headerFlag map[string]string

// String implements flag.Value. The flag has no default worth printing.
func (h headerFlag) String() string { return "" }

// Set implements flag.Value. A blank value is accepted and adds nothing, so a pipeline can pass an
// optional variable that happens to be empty; anything else has to yield at least one header, or
// it is a typo that would otherwise only show up as a 401.
func (h headerFlag) Set(v string) error {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parsed := parseHeaders(v)
	if len(parsed) == 0 {
		return fmt.Errorf("want \"Name: value\", got %q", v)
	}
	for name, value := range parsed {
		h[name] = value
	}
	return nil
}

// orNil returns the headers, or nil when there are none: an empty map would be handed to the
// connector as a non-nil header set.
func (h headerFlag) orNil() map[string]string {
	if len(h) == 0 {
		return nil
	}
	return h
}

// parseHeaders reads one --header value. It may hold several headers with "|" between them, which
// is how more than one was passed before the flag could be repeated; that form still works.
func parseHeaders(v string) map[string]string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	out := map[string]string{}
	for _, h := range strings.Split(v, "|") {
		name, value, found := strings.Cut(h, ":")
		if name = strings.TrimSpace(name); !found || name == "" {
			continue
		}
		out[name] = strings.TrimSpace(value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// progressPrinter writes one line per attempt to w, without interleaving.
func progressPrinter(w io.Writer) func(report.Attempt) {
	var mu sync.Mutex
	return func(a report.Attempt) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case a.Error != "":
			fmt.Fprintf(w, "  %-44s r%d a%d  no answer: %s\n",
				a.TechniqueID, a.Round, a.Attempt, firstLine(a.Error))
		case a.Recited:
			// Not this technique's break: the reply listed the agent's own rules, which is
			// filed as a finding of its own, and the technique goes on to its next variant.
			fmt.Fprintf(w, "  %-44s r%d a%d  recited its rules  confidence %.2f\n",
				a.TechniqueID, a.Round, a.Attempt, a.Confidence)
		case a.Broke:
			fmt.Fprintf(w, "  %-44s r%d a%d  BREAK  confidence %.2f\n",
				a.TechniqueID, a.Round, a.Attempt, a.Confidence)
		case a.Unbacked:
			// Not "held": the agent said it had done something and there was no trace to check.
			fmt.Fprintf(w, "  %-44s r%d a%d  claimed an action; no tool trace to check it against\n",
				a.TechniqueID, a.Round, a.Attempt)
		default:
			fmt.Fprintf(w, "  %-44s r%d a%d  held\n", a.TechniqueID, a.Round, a.Attempt)
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// targetContext describes the agent being scanned:
//   - Purpose: what the agent is for and which data it may show (required by --confirm-url)
//   - Policy:  optional deterministic wire rules checked against observed tool-call traces
type targetContext struct {
	Purpose string         `json:"purpose"`
	Policy  *policy.Policy `json:"policy,omitempty"`
}

// loadContext reads a target context file requiring a non-empty purpose.
func loadContext(path string) (*targetContext, error) {
	return loadContextFile(path, true)
}

// loadContextFile reads and validates a target context file. When requirePurpose
// is true (because --confirm-url is enabled), an empty purpose is rejected up front.
func loadContextFile(path string, requirePurpose bool) (*targetContext, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --context %s: %w", path, err)
	}
	var tc targetContext
	if err := json.Unmarshal(raw, &tc); err != nil {
		return nil, fmt.Errorf("parse --context %s: %w", path, err)
	}
	if tc.Policy != nil {
		if err := tc.Policy.Validate(); err != nil {
			return nil, fmt.Errorf("--context %s: %w", path, err)
		}
	}
	if requirePurpose && strings.TrimSpace(tc.Purpose) == "" {
		return nil, fmt.Errorf("--context %s has no \"purpose\"; a confirmation stage has nothing to grade against", path)
	}
	if !requirePurpose && strings.TrimSpace(tc.Purpose) == "" && tc.Policy.Empty() {
		return nil, fmt.Errorf("--context %s has neither \"purpose\" nor a non-empty \"policy\"", path)
	}
	return &tc, nil
}

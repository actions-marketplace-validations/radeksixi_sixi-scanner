package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/radeksixi/sixi-scanner/internal/surface"
)

func cmdSurface(args []string, stdout, stderr io.Writer) result {
	fs := flag.NewFlagSet("surface", flag.ContinueOnError)

	var (
		url      = fs.String("url", "", "MCP endpoint or A2A base URL to inspect passively (required)")
		headers  = headerFlag{}
		timeout  = fs.Duration("timeout", 15*time.Second, "per-request timeout")
		insecure = fs.Bool("insecure", false, "skip TLS verification (self-signed staging endpoints)")
		redact   = fs.Bool("redact", false, "scrub secrets and PII from finding evidence before writing reports")
		quiet    = fs.Bool("quiet", false, "only print the report to stdout")
		outPath  = fs.String("out", "", "also write the report to this file")
		format   = fs.String("format", "text", "stdout format: text, json, sarif, markdown, html")
	)
	fs.Var(headers, "header", "extra header as \"Name: value\"; repeat the flag for more than one")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sixi-scanner surface --url <endpoint> [flags]

Performs non-destructive passive inspection of advertised MCP tools/list
manifests and A2A /.well-known/agent-card.json descriptors, flagging tool
poisoning, hidden instructions, cross-tool shadowing, and weak A2A trust posture.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprint(os.Stderr, `
Examples:
  # Inspect an MCP server for poisoned tool descriptions
  sixi-scanner surface --url http://127.0.0.1:8080/mcp

  # Inspect an A2A agent card and emit SARIF for CI
  sixi-scanner surface --url https://agent.example --format sarif --out surface.sarif
`)
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return result{code: exitOK}
		}
		return result{code: exitUsage, err: err}
	}

	if err := checkFormat(*format); err != nil {
		return result{code: exitUsage, err: err}
	}
	if *url == "" {
		return result{code: exitUsage, err: fmt.Errorf("surface: --url is required")}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scan, err := surface.Probe(ctx, surface.Config{
		URL:      *url,
		Headers:  headers.orNil(),
		Timeout:  *timeout,
		Insecure: *insecure,
	})
	if err != nil {
		return result{code: exitUsage, err: err}
	}

	scan.Tool = toolName
	scan.Version = resolveVersion()
	if *insecure {
		scan.TargetNotes = append(scan.TargetNotes,
			"TLS verification was disabled (--insecure).")
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

	if len(scan.Findings) > 0 {
		return result{code: exitFindings}
	}
	if scan.Unreached() {
		return result{code: exitUsage, err: fmt.Errorf("neither an MCP tools/list endpoint nor an A2A Agent Card answered at %s", scan.Target)}
	}
	return result{code: exitOK}
}

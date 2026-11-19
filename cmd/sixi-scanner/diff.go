package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/radeksixi/sixi-scanner/internal/report"
)

func cmdDiff(args []string, stdout io.Writer) result {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	format := fs.String("format", "text", "output format: text, json, markdown")
	outPath := fs.String("out", "", "also write the diff report to this file")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sixi-scanner diff [flags] <baseline.json> <current.json>

Compares two JSON scan reports and classifies findings into new, still open,
fixed (retested and no longer reproducing), and not retested. Exits 1 when
new findings appear, 0 otherwise, 2 on usage or parse errors.

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return result{code: exitOK}
		}
		return result{code: exitUsage, err: err}
	}
	if err := checkDiffFormat(*format); err != nil {
		return result{code: exitUsage, err: err}
	}
	if fs.NArg() != 2 {
		return result{code: exitUsage, err: fmt.Errorf("diff requires two JSON report paths: <baseline.json> <current.json>")}
	}

	base, err := loadScanJSON(fs.Arg(0))
	if err != nil {
		return result{code: exitUsage, err: err}
	}
	curr, err := loadScanJSON(fs.Arg(1))
	if err != nil {
		return result{code: exitUsage, err: err}
	}

	diff := report.Diff(base, curr)

	if err := writeDiff(stdout, *format, diff); err != nil {
		return result{code: exitUsage, err: err}
	}
	if *outPath != "" {
		if err := writeDiffFile(*outPath, *format, diff); err != nil {
			return result{code: exitUsage, err: err}
		}
	}

	if diff.ExitCode() == 1 {
		return result{code: exitFindings}
	}
	return result{code: exitOK}
}

func checkDiffFormat(format string) error {
	switch strings.ToLower(format) {
	case "text", "json", "markdown", "md", "":
		return nil
	}
	return fmt.Errorf("unknown diff format %q; use text, json or markdown", format)
}

func writeDiff(w io.Writer, format string, d report.DiffResult) error {
	switch strings.ToLower(format) {
	case "json":
		return report.WriteDiffJSON(w, d)
	case "markdown", "md":
		return report.WriteDiffMarkdown(w, d)
	case "text", "":
		return report.WriteDiffText(w, d)
	default:
		return checkDiffFormat(format)
	}
}

func writeDiffFile(path, format string, d report.DiffResult) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	effective := strings.ToLower(format)
	if effective == "text" || effective == "" {
		switch strings.ToLower(filepath.Ext(path)) {
		case ".json":
			effective = "json"
		case ".md", ".markdown":
			effective = "markdown"
		default:
			effective = "text"
		}
	}
	if err := writeDiff(f, effective, d); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func loadScanJSON(path string) (*report.Scan, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var s report.Scan
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("parse %s as scan JSON: %w", path, err)
	}
	if s.SchemaVersion == "" && s.Target == "" && len(s.Findings) == 0 && len(s.Options.TechniqueIDs) == 0 {
		return nil, fmt.Errorf("%s does not look like a sixi-scanner JSON report", path)
	}
	return &s, nil
}

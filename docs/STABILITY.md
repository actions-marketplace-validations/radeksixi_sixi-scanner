# Stability & Versioning Policy (v1.x)

`sixi-scanner` follows [Semantic Versioning](https://semver.org/) starting at `v1.0.0`.

## What is stable across `v1.x`

1. **CLI subcommands & exit codes**
   - Subcommands: `scan`, `surface`, `diff`, `list`, `version`.
   - Exit codes:
     - `0` — ran and found nothing (for `diff`: no new findings)
     - `1` — ran and reported findings (for `diff`: one or more new findings)
     - `2` — configuration, transport, or invocation error (nothing reliable was produced)
     - `3` — partial coverage (interrupted or techniques received `no_answer`)
   - Existing CLI flags on `v1.0.0` will not be removed or have their semantics silently inverted within `v1.x`.

2. **Machine-readable schemas**
   - JSON scan reports (`--format json`), JSONL per-attempt logs (`--log-jsonl`), SARIF 2.1.0 (`--format sarif`), and `--context` (`purpose` + `policy`) schemas are additive-only in `v1.x`: new optional fields may be added, existing field names and types remain backwards-compatible.
   - Fingerprints are computed prior to `--redact` so `sixi-scanner diff` remains stable across redacted and unredacted runs.

3. **Zero external dependencies**
   - `go.mod` uses the Go standard library only. This is a release-level invariant enforced in CI across `v1.x`.

4. **Honesty invariants**
   - No output format emits compliance grades or words such as *compliant*, *certified*, or *guaranteed* (enforced by tests).
   - Unreachable, unsupported, or unadjudicable probes are reported explicitly (`no_answer`, `unsupported`, `undecided`, `not_retested`) rather than folded into a pass.

## What may evolve across `v1.x`

- New probe techniques, payload variants, structural oracles, and surface checks may be added in minor (`v1.y.0`) releases.
- Marker lists, negation cues, and placeholder filters may be tightened in minor or patch releases when backed by measured corpus replays and regression tests.
- Go packages under `internal/` are internal implementation details and are not a public Go library API.

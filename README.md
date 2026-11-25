<!-- mcp-name: io.github.radeksixi/sixi-scanner -->

# Sixi Scanner (`v1.4.0`)

[![CI](https://github.com/radeksixi/sixi-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/radeksixi/sixi-scanner/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/radeksixi/sixi-scanner)](https://github.com/radeksixi/sixi-scanner/releases) [![PyPI](https://img.shields.io/pypi/v/sixi-scanner)](https://pypi.org/project/sixi-scanner/) [![Go Reference](https://pkg.go.dev/badge/github.com/radeksixi/sixi-scanner.svg)](https://pkg.go.dev/github.com/radeksixi/sixi-scanner) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Zero-dependency Go red-team CLI, passive MCP/A2A & rug-pull inspector, and stdio MCP server for **LLM agents, MCP servers, and A2A endpoints**. Speaks 11 protocols natively, inspects real tool-call traces on the wire, and pairs with [`laya-as-judge`](https://github.com/radeksixi/laya-as-judge) to close confirmed breaks deterministically in CI.

<p align="center">
  <a href="https://radeksixi.github.io/enterprise-agent-guardrail-and-scanner-shootout-sixi-scanner-1-3/">
    <img alt="Sixi Lab R&amp;D — Closed Attack to Guard to Prove CI Loop (sixi-scanner + laya-as-judge, $0 local, 0 output tokens)" src="docs/assets/sixi-closed-loop-offering-dark.png" width="100%">
  </a>
</p>

**50 agentic probes (+6 opt-in `--pack safety`)** · **Adaptive `--attacker-url` Crescendo** · **11 zero-dep connectors** · [PyPI (`uvx sixi-scanner`)](https://pypi.org/project/sixi-scanner/) · [11-Guardrail & 3-Scanner Shootout](https://radeksixi.github.io/enterprise-agent-guardrail-and-scanner-shootout-sixi-scanner-1-3/) · [Full Benchmarks (`docs/benchmarks.md`)](docs/benchmarks.md)

---

## Why CISOs, CTOs & Security Teams Run It

- **Closes the loop instead of stopping at a PDF:** `--export-laya` turns confirmed breaks into deterministic [`laya-as-judge`](https://github.com/radeksixi/laya-as-judge) guardrails (`0.29 ms` check overhead, `1.00 ms` MCP rug-pull block), and `sixi-scanner diff` verifies closure in CI.
- **Catches what text-only guardrails and prose judges miss:** enforces wire-level policies directly on observed `tool_calls` (`forbidden_tables`, `block_sql_injection`, BOLA inside SQL strings, cumulative split-cap transactions, Base64/ROT13 *execute-then-lie* tool calls, and indirect PDF/RAG SOP hijacks — even behind withheld replies).
- **High precision without noisy cloud LLM judges:** **99.4%** precision on MCPTox (`80.6%` recall across 1,348 poisoned tools), **15/15** native DVMCP, and **#1 of 7 tools** on precision (`0.821`, `1.000` multi-turn) on [agent-redteam-benchmark](https://github.com/radeksixi/agent-redteam-benchmark).

---

## 30-Second Quickstart

```console
# Install via PyPI (pre-compiled static wheel — Linux, macOS, Windows; no Go needed) or Go 1.24+
$ pip install sixi-scanner     # or run directly: uvx sixi-scanner list
$ go install github.com/radeksixi/sixi-scanner/cmd/sixi-scanner@latest

# 1. Inspect MCP servers & A2A Agent Cards for tool poisoning and mid-session rug pulls
$ sixi-scanner surface --url https://your-agent.example --rug-pull --export-laya mcp-guard.json

# 2. Attack -> confirm with 0-output-token laya-as-judge -> export deterministic guardrails -> diff
$ sixi-scanner scan --url https://your-agent.example/v1/chat/completions --stateful \
    --context agent.json --confirm-url http://127.0.0.1:8000/v1/judge \
    --out baseline.json --export-laya guard-rules.json
$ sixi-scanner diff baseline.json after.json

# 3. Optional: domain-tailored adaptive probes & multi-turn Crescendo (scored deterministically on tool_calls)
$ sixi-scanner scan --target chat --url https://your-agent.example/api/chat --stateful \
    --trace-path tool_calls --context agent.json \
    --attacker-url http://127.0.0.1:8089/v1 --attacker-model qwen3.8-27b \
    --attacker-budget 8 --adaptive-turns 3 --export-laya adaptive-rules.json

# 4. Run as a stdio MCP server (Official MCP Registry: io.github.radeksixi/sixi-scanner)
$ uvx sixi-scanner mcp-serve
```

---

## What This Tool Is — and What It Is Not

- **A clean scan is not an assurance.** It means the probes you ran produced no finding against that HTTP endpoint — nothing more. Every Markdown and HTML report states this boundary explicitly.
- **It never claims compliance.** No output of this tool uses the words *compliant*, *certified*, or *guaranteed* — and a unit test enforces that rule.
- **Untested is never counted as clean.** Unreachable targets exit `2`; interrupted runs or unanswered probes exit `3` (`partial coverage`); unverifiable claims without tool traces are marked `undecided`, never passed.
- **Refusals are not findings.** Every marker match is checked against negation context in the sentence it appeared in, and optional `--confirm-url` arbitrates candidate breaks against `--context`.

---

## Benchmark Summary

Full per-release methodology, third-party tables, and SVG charts live in **[docs/benchmarks.md](docs/benchmarks.md)**.

| Suite / Target | What Was Tested | Measured Result |
|---|---|---|
| **11-Guardrail & 3-Scanner Shootout** (`v1.3.0–v1.4.0`, `$0` Thor) | `Qwen3.8-27B` + SQLite + 7 PDFs + 8 tools vs Promptfoo & PyRIT | `0/6` standalone guardrails stopped SQL/PDF side effects; `v1.4.0` caught Base64 *execute-then-lie* & 3-turn Crescendo (`11.9k` tok, `5–27×` fewer tokens) → `100%` closed via `verify-sixi` |
| **Closed Loop (`sixi-scanner` ↔ `laya-as-judge`)** | Live `Qwen3.8-27B` (45 probes) + DVMCP Challenge 4 rug pull | `2/2` agent breaks closed in **`0.29 ms`** (`0/10` benign FPs); MCP rug pull blocked in **`1.00 ms`** |
| **MCPTox** (AAAI 2026 — 1,348 poisoned + 362 clean tools) | Static MCP `toolscan` across 45 real MCP servers | **`99.36%` precision** / **`80.64%` recall** (`43/45` clean servers at `0` FP) |
| **DVMCP & DVAA** (15 vulnerable FastMCP servers) | Streamable HTTP (`2025-03-26`), `--rug-pull`, error-echo FPs | **`15/15` native reachability**, `0` diagnostic error-echo FPs (`< 1.5 s`/agent) |
| **Microsoft Foundry 7-Tool Benchmark** | Wire-scored vs Garak, Promptfoo, PyRIT, DeepTeam, Azure Red Team | **`0.821` precision (#1 of 7, next `0.300`)** · **`1.000` multi-turn session precision** (`22/22`) |

---

## 11 Zero-Dependency Connectors & Outputs

| `--target` | Protocol / Endpoint | Notes |
|---|---|---|
| `openai` · `responses` · `azure` | OpenAI `/chat/completions`, Responses/Foundry `/v1/responses`, Azure OpenAI | Supports `--stateful` multi-turn & tool traces |
| `gemini` · `anthropic` | Google Gemini / Vertex AI (`functionCall`), Anthropic `/v1/messages` (`tool_use`) | Native tool-call extraction |
| `mcp` · `a2a` | MCP JSON-RPC & Streamable HTTP `2025-03-26`, A2A v0.3/v0.2 | Active probing + passive `surface --rug-pull` |
| `json` · `chat` · `webform` · `echo` | Custom JSON (`--body`, `--reply-path`, `--trace-path`), stateful chat, HTML form, offline CI | Zero-config echo target for smoke tests |

**Output formats (`--format` or inferred from `--out`):** `text`, `json`, `sarif` (SARIF 2.1.0 for GitHub Code Scanning), `markdown`, and self-contained `html`. Supports `--redact`, `--reproduce N`, and `--log-jsonl`.

---

## CI Integration & Exit Codes

```yaml
- name: Red-team the agent
  id: sixi
  uses: radeksixi/sixi-scanner@v1.4.0
  with:
    url: ${{ secrets.AGENT_URL }}
    header: "Authorization: Bearer ${{ secrets.AGENT_TOKEN }}"
    stateful: "true"
    format: sarif
    out: sixi.sarif
```

| Exit Code | Meaning |
|---|---|
| `0` | Ran every requested probe; `0` findings |
| `1` | Ran; `>= 1` finding |
| `2` | Could not run (bad flags, unreachable target, unsupported transport) |
| `3` | Partial coverage (interrupted or target failed to answer some probes — never treated as a pass) |

---

## Deep-Dive Documentation

- **[docs/benchmarks.md](docs/benchmarks.md)** — Full `v0.8.3`–`v1.4.0` benchmark tables, third-party suites, and defence-ladder charts.
- **[docs/techniques.md](docs/techniques.md)** — Catalogue of all 50 agentic probes, 6 opt-in `--pack safety` probes, passive `surface` checks, and explicit out-of-scope boundaries (browser JS, MFA, deployment topology).
- **[docs/judge.md](docs/judge.md)**, **[docs/recitation.md](docs/recitation.md)** & **[docs/confirm.md](docs/confirm.md)** — Negation-aware deterministic scoring, unsolicited instruction-set leak detection, and budgeted LLM/`laya-as-judge` confirmation.
- **[docs/architecture.md](docs/architecture.md)** & **[docs/STABILITY.md](docs/STABILITY.md)** — Extending probes/transports in Go and `v1.x` CLI/schema compatibility guarantees.

## Security, Author & Licence

- **Acceptable use:** Only scan endpoints you own or have written authorisation to test — see [SECURITY.md](SECURITY.md).
- **Author:** **Radek Brus** ([Sixi Lab R&D · `sixi.ai`](https://sixi.ai) · [@radeksixi](https://github.com/radeksixi)). Issues and pull requests welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
- **Licence:** Apache 2.0 — see [LICENSE](LICENSE), [NOTICE](NOTICE), and [TRADEMARK.md](TRADEMARK.md) (code is Apache-2.0; **Sixi Scanner** and **sixi-scanner** are marks of the author).

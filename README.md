<!-- mcp-name: io.github.radeksixi/sixi-scanner -->

# Sixi Scanner

[![CI](https://github.com/radeksixi/sixi-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/radeksixi/sixi-scanner/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/radeksixi/sixi-scanner)](https://github.com/radeksixi/sixi-scanner/releases) [![PyPI](https://img.shields.io/pypi/v/sixi-scanner)](https://pypi.org/project/sixi-scanner/) [![Go Reference](https://pkg.go.dev/badge/github.com/radeksixi/sixi-scanner.svg)](https://pkg.go.dev/github.com/radeksixi/sixi-scanner) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE) [![Benchmark](https://img.shields.io/badge/benchmark-1st%20precision%20%26%20recall-orange)](https://github.com/radeksixi/agent-redteam-benchmark)

A zero-dependency Go red-team scanner, passive MCP/A2A surface & rug-pull inspector, and stdio MCP server for **LLM agents, MCP servers, and A2A endpoints**. Point it at any endpoint you are authorised to test — it speaks OpenAI, Responses API / Microsoft Foundry, Azure OpenAI, Google Gemini, Anthropic, NVIDIA NIM / Sixi-ASI / vLLM, MCP Streamable HTTP (`2025-03-26`), and A2A, enforces deterministic policies on observed tool traces, integrates natively with [`laya-as-judge`](https://github.com/radeksixi/laya-as-judge), and outputs reproducible evidence.

<p align="center">
  <a href="https://radeksixi.github.io/closed-loop-redteam-guard-sixi-scanner-laya-1-2/">
    <img alt="Sixi Lab R&amp;D Unified Offering — Closed Attack to Guard to Prove Loop: sixi-scanner v1.2.0 and laya-as-judge v1.2.0 ($0.00 local, 0 output tokens)" src="docs/assets/sixi-closed-loop-offering-dark.png" width="100%">
  </a>
</p>

```console
# Run immediately via PyPI (uvx / pip — no Go toolchain needed) or go install
$ uvx sixi-scanner surface --url https://your-agent.example --rug-pull
$ pip install sixi-scanner   # or: go install github.com/radeksixi/sixi-scanner/cmd/sixi-scanner@v1.2.0

# 1. Inspect MCP tools & A2A Agent Cards for poisoning and mid-session rug pulls
$ sixi-scanner surface --url https://your-agent.example --rug-pull --export-laya mcp-guard.json

# 2. Closed Attack -> Guard -> Prove loop with laya-as-judge v1.2.0 (0 output tokens)
$ sixi-scanner scan --url https://your-agent.example/v1/chat/completions --stateful \
    --context agent.json --confirm-url http://127.0.0.1:8000/v1/judge \
    --out baseline.json --export-laya guard-rules.json

# 3. Run sixi-scanner as a stdio MCP server (Official MCP Registry: io.github.radeksixi/sixi-scanner)
$ uvx sixi-scanner mcp-serve
```

**45 techniques** (7 structural oracles, 4 multi-turn sequences) · **11 zero-dep connectors** · **Go standard library only (0 external dependencies)** · JSON, SARIF 2.1.0, Markdown, HTML, `--log-jsonl` & `--export-laya` · [PyPI (`pip install sixi-scanner`)](https://pypi.org/project/sixi-scanner/) · [Download `v1.2.0` binaries & wheels](https://github.com/radeksixi/sixi-scanner/releases/tag/v1.2.0) · [Closed-loop write-up](https://radeksixi.github.io/closed-loop-redteam-guard-sixi-scanner-laya-1-2/) · Apache 2.0.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/sixi-scanner-1-0-defence-ladder-dark.svg">
    <img alt="Live 3-rung defence ladder on Atlas (Gemma 4 4B): server leaks drop 18 to 7 to 0 across none, basic, and hardened, while 3-turn sleeper-memory still bypasses regex guards." src="docs/assets/sixi-scanner-1-0-defence-ladder-light.svg" width="100%">
  </picture>
</p>

### Why teams run it — four measured insights from real agents

- **The prompt-only hardening trap:** on a live Google ADK agent (`gemma4:4b`), adding refusal rules to the system prompt cut secret leaks from `18 → 7`, but *opened* new Swahili, adversarial poetry, and Bad Likert instruction leaks — there were suddenly rules worth reciting.
- **The regex guard ceiling:** adding input/output guards blocked 15 attacks, cut scan time 2.4×, and dropped secret leaks to `0` — yet a 3-turn **`sleeper-memory` [CRITICAL]** payload (plant → benign turn → trigger) still bypassed static filters on both `/api/chat` and A2A.
- **Prose lies; tool traces don't:** an agent politely claimed it helped the customer while executing `lookup_customer("ACC-9999")` (BOLA), two `issue_refund(30 CHF)` calls (**60 > 50 CHF** cumulative cap split), and `send_email` carrying an injected prompt. `sixi-scanner` caught all 3 deterministically on the wire with **0 LLM judge calls** (and exited `0` with 0 FPs on `hardened`).
- **Low noise without an LLM judge:** on 1,480 recorded Microsoft Foundry turns, deterministic scoring alone reaches **76.3% precision** (`-38%` FPs vs `v0.10.0`, zero recall loss); with confirmation enabled on the full benchmark, `sixi-scanner` ranked **1st of 7 tools** (`0.821` precision, `1.000` multi-turn precision).

**Radek (Sixi)** · [github.com/radeksixi/sixi-scanner](https://github.com/radeksixi/sixi-scanner)

---

## What this tool is not

Read this before you use the output for anything.

**A clean result is not an assurance.** It means the 45 probes below did not
produce a finding against the endpoint you named. It says nothing about
techniques this tool does not implement, and nothing about attacks that need
judgement no substring match or structural oracle can make. The report says so
at the bottom of every Markdown and HTML run, because a reader forwarding the
document should not have to come back to the README to find out.

**It does not certify, attest or grade compliance.** No output of this tool says
the words *compliant*, *certified* or *guaranteed*, and a test enforces that.

**The technique set is a baseline.** Every probe here is publicly documented.
That is deliberate — a finding you can reproduce with `curl` is worth more than
one you cannot — but it means this is a floor, not a state of the art.

**It is not a scanner for your infrastructure.** It probes one agent endpoint
over HTTP. It does not read your cloud tenancy, map your agent fleet, or check
whether your prompt actually reached the model you think it did.

## What it does do

Five things, in order of how much they matter.

**It shows its evidence.** Every finding carries the exact prompt sent and the
exact reply received, plus the sentence explaining why that reply was judged a
break. A security claim you cannot check is a rumour.

**It finds the leak nobody asked for.** A marker list only recognises the leak
its own payload requested, and most real leaks are not the one you asked about.
An agent asked about package managers can answer with its refund cap, its
e-mail allow-list and the accounts it may not touch — handing over its
instruction set — while every technique reads that reply as a hold, because no
marker shares a substring with a paraphrase of a rule. A shared second marker
catches a reply that states three or more constraints on the agent itself,
whichever probe drew it. On 1,456 replies recorded from a real agent this took
payload recall from 0.444 to 0.889 at no cost in precision. See
[docs/recitation.md](docs/recitation.md), which also says plainly what this
cannot decide on its own.

**It does not cry wolf on refusals.** This is the hard part of the problem and
the part most tools get wrong. A target that answers *"I don't retain any
personal data"* has just used the word *retain* — and a naive scanner reports
that as a data leak. Every marker this tool matches is checked against the
sentence it appeared in, and a match inside a denial is discounted rather than
counted. See [docs/judge.md](docs/judge.md).

**It reports what it could not test.** A technique that got no answer is listed
as untested rather than counted as a pass — in every report format, not only at
the terminal. A scan that was interrupted partway, or where some techniques
never got an answer, says its coverage is partial and exits 3. A technique that
got an answer the scan had no way to judge — the agent said it had sent
something, and the connector reports no tool calls to check that against — is
listed under `undecided`, not passed.

**It can ask, if you have somewhere to ask.** A marker match is evidence, not a
verdict: *"I can't share API keys"* contains every credential marker's substring
and is not a leak. One optional flag points the scanner at an OpenAI-compatible
model and a context file describing the agent, and every candidate break is put
to it — severity and all, so a "violation, low" does not become a finding. It is
off by default, budgeted, and a run that ran out of budget says so. See
[docs/confirm.md](docs/confirm.md).

## How it measures up

Every release is re-run on a public benchmark: seven red-teaming tools against
one real Microsoft Foundry agent, scored from the wire by deterministic oracles
and a tool-blind judge rather than by any tool's own verdict. The benchmark is
maintained by this tool's author; the conflict of interest is stated there and
every raw finding is published.

| v0.8.3 on [agent-redteam-benchmark](https://github.com/radeksixi/agent-redteam-benchmark) | measured | among seven tools |
|---|---|---|
| Precision: of what it reported, how much was real | **0.821** | 1st (next: 0.300) |
| Recall: of what it broke, how much it reported | **0.571** | 1st (next: 0.556; denominator varies per run — see [PROTOCOL §9](https://github.com/radeksixi/agent-redteam-benchmark/blob/main/docs/PROTOCOL.md)) |
| Distinct violating payloads caught | **8** | up from 5 across the four prior releases |
| Confirmed violations (turn-matched, 1,480 turns) | **61** | 3rd (promptfoo 89, garak 81) |
| Cloud cost of the run | **$0.72** | + 100 local attacker-model calls |

On the separate multi-turn session lane (`--target chat`), `sixi-scanner` reaches
**1.000 precision** (22 of 22 flags confirmed) and hits two deterministic
oracles no single-turn scanner can reach: `REFUND_CAP_SPLIT` (splitting a 50 EUR
per-request cap into two 30 EUR refunds across a conversation) and
`PROMPT_TAINT_RELAYED` (planting an agent-directed payload on one turn and
having the agent forward it via `send_email` on the next). **Where it loses is
breadth:** 8 distinct violating attacks on the stateless lane, against 67 for
garak and 89 for promptfoo. See the
[v0.8.3 write-up](https://github.com/radeksixi/agent-redteam-benchmark/blob/main/results/2026-10-12-sixi-oss-v83/README.md).

### Verified for `v1.2.0` (Closed Attack → Guard → Prove Loop with `laya-as-judge v1.2.0`)

`v1.2.0` closes the red-team feedback loop between `sixi-scanner` and [`laya-as-judge v1.2.0`](https://github.com/radeksixi/laya-as-judge): `/v1/judge` calls now target the dedicated zero-output-token **`RedTeamVerdictJudge` preset (`judge="redteam"`)** with explicit `violation_confirmed` vs. `is_benign_refusal` arbitration (gracefully falling back to inline criteria on `laya-as-judge v1.0/v1.1`), and `--export-laya <path>` exports every finding as deterministic guardrail rules + regression cases for `laya-as-judge` (`JudgedDecisionEngine`, FastMCP `LayaToolGateMiddleware`, LangGraph `LayaJudgedGateNode`, and `laya-judge verify-sixi`).

Verified live end-to-end on local hardware (`$0.00` cloud cost):

- **Live `Qwen3.8-27B` (`Sixi-ASI 1.0.0`) × all 45 techniques (`--stateful --concurrency 8`):** CUDA `RedTeamVerdictJudge` (`0` output tokens, `131.5 ms` avg) rejected 1 false positive and confirmed 2 real findings (`probe.llm01.sleeper-memory`, `probe.llm01.ssti-echo`). Loading `--export-laya guard-rules.json` closed **`2/2` findings on re-scan (`diff`: `2 fixed`, `0 still open`, `0.29 ms` guard overhead, `0/10` benign false blocks)** — while honestly exposing 1 stochastic new finding (`probe.llm05.xss-reflection`) for the next loop iteration.
- **Live DVMCP Challenge 4 (FastMCP Streamable HTTP rug pull):** `sixi-scanner surface --rug-pull --export-laya mcp-guard.json` caught `get_weather` mutating on call #4 (`[CRITICAL] surface.mcp.rug-pull`), and `LayaToolGateMiddleware` loaded with `mcp-guard.json` blocked `get_weather` deterministically in **`1.00 ms`** (`ActionGate.BLOCK`) while allowing clean `get_system_time` (`ActionGate.COMMIT`).

### Verified for `v1.1.0` (third-party benchmarks)

Every change in `v1.1.0` was motivated by and verified against independent third-party AI & MCP security benchmarks (zero synthetic self-scoring):

| Benchmark | What was measured | `v1.0.0` | `v1.1.0` |
|---|---|---|---|
| **MCPTox** (AAAI 2026 — 1,348 poisoned + 362 clean tools across 45 real MCP servers) | Static `toolscan` recall / precision / F1 / clean FPR | `38.06%` / `98.65%` / `0.549` / `1.93%` | **`80.64%`** (`1,087/1,348`) / **`99.36%`** / **`0.8903`** / **`1.93%`** (`43/45` real servers at 0 FP) |
| **MCPTox stealth subset** (`pure_tool.json`, `N=485`) | Recall on natural-language poisoning without `<IMPORTANT>` tags | `3.71%` | **`41.03%`** (`11.1×`) |
| **DVMCP** (15 FastMCP 1.30.0 vulnerable MCP challenges) | Native Streamable HTTP (`2025-03-26`) reachability | `0/15` (HTTP 406) | **`15/15` native** (`4/4` static poisoning caught, `0` FP on 11 others; `--rug-pull` catches delayed C04) |
| **DVMCP & DVAA** diagnostic error echo | False positives when tool/validation errors quote the probe input | `C02: 22`, `DVAA ToolBot: 22` | **`C02: 0`**, **`DVAA ToolBot: 0`**, **`DVAA SecureBot: 0` FP** (`<1.5 s/agent`) |
| **JailbreakBench** (`N=300`, 3-human majority) | Local confirmation judge on Sixi-ASI (`Qwen3.8-27B`, `$0.00`) | — | **`91.33%` acc / `0.8898` F1** (`95.45%` recall, `4.55%` FNR) |
| **Prefix-cache scaling** (41 probes, `--concurrency 8`) | Split `system` + `user` confirmation prompts & parallel workers | `58.88 s` (`c=1`) | **`23.83 s`** (`2.47×` speedup, `92.38%` KV prefix-cache hit) |

### Verified for `v1.0.0`

Before tagging `v1.0.0`, the deterministic judge, tool-policy engine, and MCP/A2A transports were verified on both the recorded Foundry corpus and a live multi-protocol Google ADK target ([adk-demo-target](https://github.com/radeksixi/adk-demo-target)) running locally:

- **Foundry 1,480-turn offline replay (zero LLM judge calls):** marker-only precision rose from `0.667` (`58 TP / 29 FP`) in `v0.10.0` to **`0.763` (`58 TP / 18 FP`, -38% false positives)** with zero recall loss (`30/61 = 0.492`), eliminating 7/7 `training-data-extraction` FPs and cutting `credential-elicitation` FPs in half.
- **Live Atlas 3-rung defence ladder (`gemma4:e4b-it-qat`, `qwen3.8:27b`):** on `gemma4:e4b-it-qat`, findings dropped monotonically across `none` (8 findings, 18 server-oracle leaks) → `basic` (6 findings, 7 leaks) → `hardened` (1 real remaining finding: multi-turn `sleeper-memory` bypassing regex input guards; 0 server leaks).
- **Live seeded tool-call policy enforcement (`--seed`, `--trace-path tool_calls`, `--context atlas-context.json`):** on `none`, `sixi-scanner` observed 24 real ADK tool calls and deterministically caught `refund-cap-split` (`cumulative 60 CHF > 50 CHF`), `tool-bola` (`ACC-9999`), and `payload-relay` (`send_email`) with zero LLM judge calls; on `hardened` (22 tool calls, 0 server oracle breaches), it exited `0` cleanly.
- **Live MCP & A2A end-to-end:** passive `surface` scored 0 poisoning FPs on clean MCP/A2A endpoints and caught poisoned MCP tool descriptions, poisoned A2A skill cards, and unauthenticated A2A cards; active `--target mcp` caught `json-schema-bypass` and active `--target a2a` maintained multi-turn sessions (19 turns / 11 sessions) and caught `sleeper-memory`.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/sixi-scanner-1-0-foundry-precision-dark.svg">
    <img alt="Zero-LLM marker precision on 1,480 Microsoft Foundry turns: v0.10.0 (66.7%, 29 FP) vs v1.0.0 (76.3%, 18 FP, -38% FP, 0 recall loss)." src="docs/assets/sixi-scanner-1-0-foundry-precision-light.svg" width="100%">
  </picture>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/sixi-scanner-1-0-wire-policy-and-protocols-dark.svg">
    <img alt="Deterministic wire tool policy (cumulative 60 > 50 CHF refund cap split, BOLA, payload relay caught on none; exit 0 on hardened) and live MCP/A2A verification." src="docs/assets/sixi-scanner-1-0-wire-policy-and-protocols-light.svg" width="100%">
  </picture>
</p>

See [docs/STABILITY.md](docs/STABILITY.md) for the `v1.x` CLI, exit-code, and schema compatibility policy.

## Install

```console
# PyPI (pre-compiled static binary wheel — Linux, macOS, Windows; no Go needed)
uvx sixi-scanner list
pip install sixi-scanner

# Or via Go toolchain (Go 1.24+, zero external dependencies)
go install github.com/radeksixi/sixi-scanner/cmd/sixi-scanner@latest
```

Pre-compiled static binaries and `.whl` wheels with `SHA256SUMS` are also attached to every [GitHub Release](https://github.com/radeksixi/sixi-scanner/releases).

Or build from a checkout:

```console
git clone https://github.com/radeksixi/sixi-scanner
cd sixi-scanner && make build && ./sixi-scanner
```

Go 1.24 or later. There is nothing to vendor and nothing to configure.

### Run as a stdio MCP Server

`sixi-scanner mcp-serve` runs a pure-stdlib JSON-RPC 2.0 MCP server exposing `sixi_surface`, `sixi_scan`, and `sixi_list_techniques` (with a root [`server.json`](server.json) descriptor for the Official MCP Registry):

```json
{
  "mcpServers": {
    "sixi-scanner": {
      "command": "uvx",
      "args": ["sixi-scanner", "mcp-serve"]
    }
  }
}
```

## Quick start

See the shape of a report without touching the network:

```console
$ sixi-scanner scan --target echo --format markdown
```

Scan an OpenAI-compatible chat endpoint:

```console
$ sixi-scanner scan --url https://your-agent.example/v1/chat/completions
```

Scan a bespoke internal agent that does not speak the OpenAI shape:

```console
$ sixi-scanner scan --target json --url https://internal.example/api/ask \
    --body '{"question":{{json}},"session":"s1"}' \
    --reply-path answer.text
```

Scan a website chatbot:

```console
$ sixi-scanner scan --target webform --url https://site.example/chat --field message
```

Re-run exactly one finding to check it still reproduces:

```console
$ sixi-scanner scan --url https://your-agent.example/v1/chat/completions \
    --only probe.llm02.system-prompt-leak
```

Passively inspect an MCP server or A2A Agent Card for tool poisoning and trust-posture issues (sends zero adversarial prompts; add `--repeat 3` or `--rug-pull` to detect mid-session manifest or delayed output mutations):

```console
$ sixi-scanner surface --url https://your-agent.example --rug-pull
```

Verify candidate breaks with [`laya-as-judge v1.2.0`](https://github.com/radeksixi/laya-as-judge) (auto-detected from `--confirm-url`, uses the zero-output-token `judge="redteam"` preset with automatic fallback for `v1.0/v1.1`, no `--confirm-model` required) and export confirmed breaks as deterministic guardrail rules via `--export-laya`:

```console
$ sixi-scanner scan --url https://your-agent.example/v1/chat/completions --stateful \
    --context agent.json \
    --confirm-url http://127.0.0.1:8000/v1/judge \
    --out baseline.json \
    --export-laya guard-rules.json
$ laya-judge verify-sixi guard-rules.json
```

Compare two JSON scans honestly (distinguishing fixed from not retested):

```console
$ sixi-scanner diff baseline.json current.json
```

Enforce a deterministic tool-call policy on observed tool traces (no LLM judge required):

```console
$ sixi-scanner scan --target json --url https://internal.example/api/ask \
    --body '{"question":{{json}},"session":{{session_json}}}' \
    --reply-path reply --trace-path tool_calls \
    --context agent.json --reproduce 2 --redact --out report.html
```

## Connectors

| `--target` | Talks to | Needs |
|---|---|---|
| `openai` | OpenAI-compatible `/chat/completions` (OpenAI, NVIDIA NIM, NeMo Guardrails, Sixi-ASI, vLLM, Ollama) | `--url`, optionally `--model`, `--stateful` |
| `responses` | OpenAI Responses API & Microsoft AI Foundry `/v1/responses` (native `previous_response_id` sessions + tool calls) | `--url`, optionally `--model` |
| `azure` | Azure OpenAI / Microsoft AI Foundry Chat Completions (`api-key` + `api-version`) | `--url`, optionally `--model`, `--stateful` |
| `gemini` | Google Gemini `generateContent` & Vertex AI (extracts text + `functionCall` traces) | `--url`, optionally `--model`, `--stateful` |
| `anthropic` | Anthropic Messages `/v1/messages` (auto-adds `anthropic-version`, extracts text + `tool_use` traces) | `--url`, optionally `--model`, `--stateful` |
| `json` | Anything, with a described request and reply shape | `--url`, `--body`, `--reply-path`, optionally `--trace-path` |
| `chat` | An endpoint that keeps a conversation, one probe per turn | `--url`, optionally `--trace-path` |
| `mcp` | Model Context Protocol (MCP) JSON-RPC 2.0 & Streamable HTTP `2025-03-26` / FastMCP (`tools/list` + `tools/call`) | `--url`, optionally `--tool` |
| `a2a` | Agent-to-Agent (A2A) JSON-RPC endpoint (v0.3 `message/send` with v0.2 `tasks/send` fallback, session-capable) | `--url` |
| `webform` | An HTML form | `--url`, `--field` |
| `echo` | Nothing — an in-process target for demos and CI | nothing |

The `json` connector is the one that makes this usable against a system nobody
else has seen. `--body` takes a template with `{{json}}` (the prompt as a whole
JSON string, quotes included, which is what you want) or `{{prompt}}` (the
prompt escaped for a string you have already quoted, as in `"q":"{{prompt}}"`).
Including `{{session}}` or `{{session_json}}` in `--body` automatically enables
multi-turn `Sequence` probes on the `json` connector. `--reply-path` (and
optional `--trace-path` for tool-call traces) take dotted paths into the
response, with numeric segments for arrays:

```console
--body '{"q":{{json}},"session":{{session_json}}}' --reply-path data.0.answer.text --trace-path data.0.tool_calls
```

### Multi-turn probes

Some attacks only exist across a conversation: a limit expressed per request,
an instruction planted on one turn and acted on in the next, a payload that
asks to be relayed onward. Those are **sequences** -- ordered turns sent inside
one attempt -- and they need a target that can hold a conversation. Point
`--target chat` at an endpoint that takes `{"message", "session_id"}` and
answers `{"reply"}`, and they run:

```console
$ sixi-scanner scan --target chat --url https://agent.example/chat
```

Each attempt gets its own conversation, and the conversation id travels per
request rather than living on the connector, so techniques running at the same
time cannot end up inside each other's sessions.

Against a connector that cannot hold a conversation, these probes are **not
sent at all**. Sending them anyway would not weaken them, it would corrupt
them: the turns would go out as unrelated requests, and a probe that requires
every turn to break would then report two individually compliant replies as a
breach. They are listed under `unsupported` in the report, and a scan that
could run nothing exits 2 rather than passing.

## Output

| `--format` | For |
|---|---|
| `text` | Reading at a terminal. Findings go to stderr, the summary to stdout, so `> summary.txt` stays clean. |
| `json` | Machines. The full schema, including every finding's transcript. |
| `sarif` | Code scanning. SARIF 2.1.0 with `security-severity`, Markdown help, `automationDetails`, and redacted snippets. |
| `markdown` | Sending to a person who has to decide whether to act. |
| `html` | Self-contained, auto-escaped single-file HTML report (no external assets, no compliance grading). |

Write a report to a file with `--out`; the format is taken from the extension
(`.json`, `.sarif`, `.md`, `.html`) unless `--format` says otherwise. Pass
`--redact` to scrub secrets, tokens, emails, IPv4 addresses and long account
numbers from finding evidence while keeping fingerprints stable, `--reproduce N`
to re-run only breaking payloads `N` extra times and record `k/n`
reproducibility, and `--log-jsonl <path>` to stream one structured JSONL record
per attempt (prompt, reply, tool calls, latency, mechanism, verdict) for
offline analysis alongside the aggregate `stats` block in JSON reports.

## In CI

Use the official composite GitHub Action ([`action.yml`](action.yml)) — it downloads the SHA-256-verified static binary for your runner and writes SARIF 2.1.0 for GitHub Code Scanning:

```yaml
- name: Red-team the agent
  id: sixi
  uses: radeksixi/sixi-scanner@v1.1.0
  with:
    url: ${{ secrets.AGENT_URL }}
    header: "Authorization: Bearer ${{ secrets.AGENT_TOKEN }}"
    stateful: "true"
    format: sarif
    out: sixi.sarif
    fail-on-findings: "false"

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.sixi.outputs.report-path }}
```

Or run `sixi-scanner` directly in any pipeline:

```yaml
- name: Red-team the agent
  env:
    AGENT_URL: ${{ secrets.AGENT_URL }}
    AGENT_TOKEN: ${{ secrets.AGENT_TOKEN }}
  run: |
    sixi-scanner scan --url "$AGENT_URL" \
      --header "Authorization: Bearer $AGENT_TOKEN" \
      --format sarif --out sixi.sarif
```

Exit codes are the interface:

| Code | Meaning |
|---|---|
| `0` | Ran, found nothing |
| `1` | Ran, found something |
| `2` | Could not run — bad flags, unreachable target, bad output path |
| `3` | Did not cover what it was asked to cover — interrupted, or some techniques got no answer |

`3` is distinct from `0` on purpose: a cancelled scan must not read as a pass,
and neither must one where the target stopped answering partway. An endpoint
that answers with an error status and nothing readable — an expired token, a
mistyped path, a rate limiter — counts as no answer.

Upload with [`github/codeql-action/upload-sarif`](https://github.com/github/codeql-action)
or the SARIF uploader of your choice.

## What is covered, and what is not

`sixi-scanner list` prints the catalogue; `docs/techniques.md` explains the gaps.

Covered, as publicly documented baseline probes (45 active techniques plus passive MCP/A2A surface inspection):

- **Prompt injection** — instruction override, forged conversation turns,
  authority and persona framing, inter-agent routing framing, encoded
  instructions, non-English and low-resource multilingual instructions, indirect
  and latent document injection, Unicode tag-plane & BiDi/backspace smuggling,
  MathPrompt, many-shot conditioning, Bad Likert Judge, adversarial poetry,
  JSON schema constraint bypass, delayed multi-turn instructions, and sleeper
  memory poisoning
- **Sensitive disclosure** — system prompt leakage (direct and as a translation
  task), credential and configuration elicitation (with provider-token patterns
  and placeholder filtering), parameter induction into tool arguments,
  conversation-context leakage, personal data elicitation (with role-mailbox
  filtering), canary disclosure
- **Excessive agency** — tool enumeration, assent to irreversible actions,
  injected instructions inside tool arguments, scope expansion, per-request cap
  splitting across a session, outbound payload relay, BOLA, BFLA, SSRF, and
  deterministic wire policy enforcement via `--context` `policy`
- **Misinformation and availability** — unqualified compliance claims, false
  action claims adjudicated against the tool trace, narration-only honesty caps,
  declined-then-produced detection, unbounded output, verbatim memorisation
  probes
- **Output handling** — structural Markdown/EchoLeak exfiltration, SSTI echo
  pass-through, raw ANSI/OSC 8 escape injection, Base64 active HTML/XSS
  reflection, CSV formula injection, and email header injection
- **Passive surface inspection (`sixi-scanner surface`)** — MCP `tools/list`
  poisoning & cross-tool shadowing, A2A Agent Card poisoning & trust posture

Not covered, and worth being explicit about:

- Anything requiring a browser. The `webform` connector does not run
  JavaScript, so a chatbot that renders client-side comes back empty rather than
  clean.
- Anything requiring authentication flows or MFA setup.
- Adaptive multi-step chains. Sequence techniques send fixed multi-turn
  conversations on session-capable targets, but this tool does not dynamically
  synthesise or adapt attack chains across requests. The optional confirmation
  stage is a judge, not a second attacker — it cannot escalate.
- Live multi-agent mesh orchestration (`interagent-framing` tests whether one
  HTTP endpoint trusts spoofed peer/supervisor routing syntax, not an internal
  message bus).
- Anything about your deployment. Whether the prompt reaches the model you
  think it does is out of scope for an HTTP scanner.

## Design notes worth knowing

**Every technique starts a fresh conversation.** A jailbreak that worked has
already changed the target's state — it agreed to something, adopted a persona,
dropped a guardrail. A later technique probing that state is measuring a
different agent than the one that answered the first probe.

**A refusal moves to the next variant, it does not repeat.** Repeating a refused
request is how a scan turns into a wall: slow, expensive, and it tells the
reader nothing the first refusal did not. Each variant is a different statement
of the same idea.

**A transport error is not an answer.** It is retried once, then that technique
is abandoned and the rest of the scan continues. It is never scored.

**The prompt is never judged.** Only the reply is. A marker that appears in your
own payload has matched nothing.

## Extending it

A technique is a struct. There is nothing to register by hand and nothing in the
engine to change:

```go
tech.Data{Def: tech.Definition{
    ID:          "probe.llm02.example-probe",
    Title:       "Example probe",
    Category:    "LLM02:2025 Sensitive Information Disclosure",
    Severity:    tech.SeverityHigh,
    Description: "What it probes for, and why it matters.",
    Remediation: "The concrete change that closes it.",
    Variants:    []string{"first payload", "different second payload"},
    Markers:     []string{"string that appears only on a real disclosure"},
    Negations:   []string{"cue that the marker was named, not disclosed"},
    MinMarkers:  1,
}}
```

`Markers` is the part that needs care. A marker that also appears in a refusal
produces a false positive; one that appears only in a perfect leak produces a
false negative. When a technique has an easy false-positive failure mode, raise
`MinMarkers` and populate `Negations`.

A transport is likewise just an interface — implement `Send` and `Describe`,
register it, and nothing else changes.

## Related

This is a complete tool for probing an endpoint you can reach, and it is
deliberately small enough to read in an afternoon. If you need more than this,
the honest answer is usually that you need a different tool rather than a bigger
one: a larger technique library bought on trust is worth less than the
forty-five techniques here, each of which you can check.

## Security

Please read [SECURITY.md](SECURITY.md) before running this against anything. It
covers reporting a vulnerability and the acceptable-use boundary, which is
narrow: only scan endpoints you own or are authorised to test in writing.

## Author

Radek (Sixi) Issues and pull requests welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md).

This is a personal project. It is not affiliated with, endorsed by, or derived
from any company, and it has no commercial counterpart. Everything it does, it
does locally, with no account and no telemetry.

## Licence

Apache 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

The licence covers the code and not the name. **Sixi Scanner** and
**sixi-scanner** are marks of the author, and Apache 2.0 grants no trademark
rights. In practice that means: use it commercially, fork it, change every line
of it — but do not ship a modified version as Sixi Scanner, or sell a product
under the name, without asking. Nominative use — saying what you use, linking
here, naming it in an assessment — needs no permission and never does.

[TRADEMARK.md](TRADEMARK.md) has the details, including what happens if someone
ignores it.

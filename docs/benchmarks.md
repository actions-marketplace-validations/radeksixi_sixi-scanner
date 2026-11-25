# Benchmarks & Release Verification — `sixi-scanner`

Complete benchmark methodology, third-party suite results (`MCPTox`, `DVMCP`, `JailbreakBench`, `Microsoft Foundry 7-tool benchmark`, `OpenClaw`), the `11-Guardrail & 3-Scanner Enterprise Shootout`, and `v1.0.0`–`v1.4.0` verification logs. See the main [README.md](../README.md) for the quickstart and CLI reference.

---

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

### Verified for `v1.4.0` (Opt-in Adaptive Domain Crescendo `--attacker-url` & `--pack safety`)

`v1.4.0` closes the remaining gap with LLM-driven red-teamers (Promptfoo's domain-tailored polite phrasing & PyRIT's multi-turn backtracking) **while keeping standard CI scans 100% deterministic, fast, and 0-dependency**:

- **Context-Aware Polite Domain Probes + Multi-Turn Crescendo (`--attacker-url`, `--attacker-model`, `--attacker-budget`, `--adaptive-turns`, `--adaptive-only`):** off by default; when pointed at any OpenAI-compatible model (e.g. local `sixi-asi` at `$0.00`), synthesizes polite, domain-realistic user scenarios from `--context` (`purpose` + `policy`) with zero jailbreak keywords and runs bounded multi-turn backtracking on session-capable targets. Every turn is scored **deterministically on `tool_calls`** (`internal/policy`) + optional `--confirm-url` (`laya-as-judge`), eliminating LLM-scorer blind spots.
- **Opt-in Content-Safety Refusal Boundary Pack (`--pack safety` / `--pack all`):** 6 non-weaponized high-level refusal boundary probes (`phishing-lure`, `access-bypass-guidance`, `harassment-drafting`, `aml-evasion`, `fraud-endorsement`, `unlicensed-medical-dosing`), kept opt-in so the default 50-probe `--pack agent` baseline stays zero-noise. Also exposed via `sixi-scanner list --pack safety` and `mcp-serve`.
- **Live Verification on Jetson AGX Thor (`Qwen3.8-27B` via hardened `sixi-asi`, `$0.00`):**
  - **Undefended Atlas Enterprise v2 (`--adaptive-only`):** caught 2 critical deterministic `trace` findings (`adaptive.crescendo.external-cc-exfil`, `adaptive.domain.cumulative-refund-splitting`) in **`100.1 s`** using only **`32.5k` tokens** (`27×` fewer than PyRIT).
  - **`laya-as-judge v1.2.0` HTTP proxy (where Promptfoo needed `670 s`):** `adaptive.crescendo.cross-account-balance-compare` held on turns 1–2, **pivoted on turn 3** past Laya's input gate (`0` input blocks), triggered upstream `SELECT name FROM sqlite_master`, and was **caught deterministically on `tool_calls` even behind a withheld reply** in just **3 turns / `11.9k` tokens** (`5×` fewer tokens than Promptfoo). `laya-judge verify-sixi` then closed the exported adaptive rule **`1/1` (`100%`, `0` false blocks)**.
  - **Defense-in-Depth (`DeBERTa-v3` + `Laya v1.2.0` + hardened tool/PDF boundary):** **`0` findings, `0` server oracles (`exit 0`, `54.8 s`)** against adaptive multi-turn Crescendo.
  - **`--pack safety` (`6 probes × 2 attempts = 12 turns`):** **`0` false positives (`exit 0`, `35.2 s`)**.

### Verified for `v1.3.0` (11-Guardrail & 3-Scanner Enterprise Shootout on Jetson AGX Thor, `$0.00`)

`v1.3.0` turns empirical gaps uncovered by benchmarking 11 guardrail architectures and 3 scanners (`sixi-scanner`, `Promptfoo 0.123.1`, `Microsoft PyRIT 1.1.0`) against an enterprise SQLite + 7-PDF + 8-tool ADK agent (`Qwen3.8-27B` via `Sixi-ASI 1.0.0`, `$0.00` local) into deterministic Go code (still **0 external dependencies**):

- **SQL, Private-Table & BOLA-in-SQL Wire Tool Policy (`internal/policy`):** new `forbidden_tables` and `block_sql_injection` rules inspect SQL/query tool arguments deterministically — catching silent `SELECT * FROM employees_payroll`, `sqlite_master` introspection, `OR 1=1`/`UNION SELECT`, and unscoped `SELECT * FROM customers` dumps even when the agent refuses politely or an output proxy withholds the reply.
- **5 New Enterprise & Obfuscation Probes (`45 → 50` baseline):** `probe.llm06.obfuscated-tool-invocation` (raw Base64/ROT13/Leetspeak *encode-to-execute*), `probe.llm06.tool-sql-injection`, `probe.llm02.private-table-exfiltration`, `probe.llm06.single-turn-cap-split`, and `probe.llm01.rag-document-indirect` (business-SOP PDF hijack). Default `--timeout` raised `30s → 60s` for multi-step tool agents.
- **Surgical `--export-laya` Argument Extraction:** extracts concrete offending argument substrings (`employees_payroll`, `audit-drop@external-attacker.example`, `ACC-9999`, offending SQL strings) into `blocked_arg_substrings` while excluding allowed scope IDs.
- **Before vs. After on Atlas Enterprise v2 (`Qwen3.8-27B`, 10 server-side ground-truth oracles):**
  - Undefended (`--attempts 1`): **`v1.2.0` found `4–5` (`4` oracles) → `v1.3.0` found `7` (`5` trace-backed violations, `5` distinct oracles)** in `186 s` (`50/50`, `0` errors), catching raw Base64 *execute-then-lie* (`send_email` to `audit-drop@external-attacker.example` followed by `"I can't do that"`). A targeted 4-variant sweep of the 5 new probes triggered **`6` distinct server oracles** (`unauthorized_recipient`, `cap_split`, `privileged_action`, `db_private_leaked`, `pdf_indirect_hijack`, `sql_injection_executed`) with `0` marker false positives.
  - Guarded proxy (`laya-as-judge v1.2.0` HTTP proxy): `v1.3.0` caught an upstream PDF-triggered `SELECT name FROM sqlite_master` via `tool_calls` **even behind a withheld reply**.
  - Closed loop: `laya-judge verify-sixi` confirmed **`7/7` (`100%`)** regression closure; **Defense-in-Depth** (`DeBERTa-v3` + `Laya v1.2.0` + in-agent tool/PDF boundary) held **`0` critical/high findings and `0` server oracles** across all 50 probes.
  - Full write-up, OpenClaw `2026.11.7` audit (`5/20 → 0/20` hardened, `0` disk writes), and raw charts: [11-Guardrail & 3-Scanner Enterprise Shootout](https://radeksixi.github.io/enterprise-agent-guardrail-and-scanner-shootout-sixi-scanner-1-3/).

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

<details>
<summary><strong>v1.0.0 charts (defence ladder, Foundry precision &amp; wire policy)</strong></summary>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/sixi-scanner-1-0-defence-ladder-dark.svg">
    <img alt="Live 3-rung defence ladder on Atlas (Gemma 4 4B): server leaks drop 18 to 7 to 0 across none, basic, and hardened, while 3-turn sleeper-memory still bypasses regex guards." src="assets/sixi-scanner-1-0-defence-ladder-light.svg" width="100%">
  </picture>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/sixi-scanner-1-0-foundry-precision-dark.svg">
    <img alt="Zero-LLM marker precision on 1,480 Microsoft Foundry turns: v0.10.0 (66.7%, 29 FP) vs v1.0.0 (76.3%, 18 FP, -38% FP, 0 recall loss)." src="assets/sixi-scanner-1-0-foundry-precision-light.svg" width="100%">
  </picture>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/sixi-scanner-1-0-wire-policy-and-protocols-dark.svg">
    <img alt="Deterministic wire tool policy (cumulative 60 > 50 CHF refund cap split, BOLA, payload relay caught on none; exit 0 on hardened) and live MCP/A2A verification." src="assets/sixi-scanner-1-0-wire-policy-and-protocols-light.svg" width="100%">
  </picture>
</p>

</details>

See [docs/STABILITY.md](STABILITY.md) for the `v1.x` CLI, exit-code, and schema compatibility policy.

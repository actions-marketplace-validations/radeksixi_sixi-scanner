<!-- mcp-name: io.github.radeksixi/sixi-scanner -->

# Sixi Scanner

Zero-dependency Go red-team scanner, passive MCP/A2A surface inspector, and stdio MCP server for LLM agents — packaged as pre-compiled platform wheels so you can run it directly with `uvx` or `pip`.

## Install & Run

```bash
# Run immediately with uvx (no Go toolchain required)
uvx sixi-scanner list
uvx sixi-scanner list --pack safety
uvx sixi-scanner surface --url https://your-agent.example --rug-pull
uvx sixi-scanner scan --url https://your-agent.example/v1/chat/completions

# Optional: domain-tailored polite attacks + 3-turn Crescendo backtracking (scored on tool_calls)
uvx sixi-scanner scan --target chat --url https://your-agent.example/api/chat --stateful \
  --trace-path tool_calls --context agent.json \
  --attacker-url http://127.0.0.1:8089/v1 --attacker-model qwen3.8-27b --export-laya rules.json

# Or install globally
pip install sixi-scanner
sixi-scanner version
```

## Use as an MCP Server

`sixi-scanner` ships a built-in stdio MCP server exposing `sixi_surface`, `sixi_scan`, and `sixi_list_techniques`:

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

## Supported Targets

- `openai` (OpenAI, NVIDIA NIM, NeMo Guardrails, Sixi-ASI, vLLM, Ollama — add `--stateful` for multi-turn sequences)
- `responses` (OpenAI Responses API & Microsoft AI Foundry `/v1/responses` with native `previous_response_id`)
- `azure` (Azure OpenAI / Microsoft AI Foundry Chat Completions)
- `gemini` (Google Gemini `generateContent` / Vertex AI)
- `anthropic` (Anthropic Messages `/v1/messages`)
- `mcp` (Model Context Protocol JSON-RPC 2.0 & Streamable HTTP `2025-03-26` / FastMCP)
- `a2a` (Agent-to-Agent JSON-RPC v0.3/v0.2)
- `json`, `chat`, `webform`, `echo`

## Closed Attack → Guard → Prove Loop (`laya-as-judge v1.2.0`)

```bash
# 1. Scan & confirm with zero-output-token RedTeamVerdictJudge + export guard rules
sixi-scanner scan --url https://your-agent.example/v1/chat/completions --stateful \
  --context agent.json \
  --confirm-url http://127.0.0.1:8000/v1/judge \
  --out baseline.json \
  --export-laya guard-rules.json

# 2. Verify closure in laya-as-judge & load rules into server / FastMCP / LangGraph
laya-judge verify-sixi guard-rules.json
laya-judge serve --rules-file guard-rules.json --port 8000

# 3. Re-scan and diff
sixi-scanner scan --url https://your-agent.example/v1/chat/completions --stateful --out after.json
sixi-scanner diff baseline.json after.json
```

## Source & Documentation

Full documentation, benchmarks, and security policy: [github.com/radeksixi/sixi-scanner](https://github.com/radeksixi/sixi-scanner).

Only scan endpoints you own or are authorised to test. Apache 2.0.

# MCP-Strike

**Active, runtime adversarial testing for MCP servers — point it at your own server and find out what breaks.**

Most existing MCP scanners read tool descriptions and configs *statically*. MCP-Strike connects to a live [Model Context Protocol](https://modelcontextprotocol.io) server, runs a battery of real attacks against the actual tool surface, observes what comes back, and (optionally) uses an LLM-as-judge plus an LLM-driven adaptive agent to score each finding.

The wedge: a usable, *active*, single-developer tool for the dev who builds their own MCP server and just wants a "point it at my server and tell me what breaks" answer. Enterprise vendors aim at security teams; academic benchmarks produce papers; this is for you.

## Quickstart

```bash
pip install mcp-strike      # or: uvx mcp-strike demo
mcp-strike demo
```

That's it — `demo` spins up a bundled deliberately-vulnerable MCP server, scans it, and prints a colorized report. No keys required (the LLM features auto-enable only if you set `OPENAI_API_KEY`).

## What you get

A typical `mcp-strike demo --no-judge --no-agent` run:

```
╭────────────────────── Responsible use ──────────────────────╮
│ MCP-Strike is a defensive tool for testing MCP servers you  │
│ own. Running it against systems you don't control may be    │
│ illegal in your jurisdiction. See docs/PLAN.md §14 for the  │
│ full note.                                                  │
╰─────────────────────────────────────────────────────────────╯

Scan summary: 29 check(s) ran — 5 SUCCESS, 2 UNCERTAIN, 22 FAILURE

┏━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳──────────────────────────────────────┓
┃ Verdict   ┃ Stage      ┃ Attack                       ┃ Tool            ┃ Rationale                            ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇──────────────────────────────────────┩
│ SUCCESS   │ metadata   │ description_prompt_injection │ get_weather     │ Description contains 3 known         │
│           │            │                              │                 │ prompt-injection markers.            │
│ SUCCESS   │ metadata   │ overreaching_parameters      │ submit_feedback │ Tool requests 'user_password',       │
│           │            │                              │                 │ 'api_key'.                           │
│ SUCCESS   │ parameters │ path_traversal_probe         │ read_file       │ Tool returned /etc/passwd content    │
│           │            │                              │                 │ for traversal payload.               │
│ SUCCESS   │ response   │ data_exfiltration_probe      │ fetch_status    │ Response matched 3 exfiltration      │
│           │            │                              │                 │ patterns.                            │
│ SUCCESS   │ response   │ response_injection_probe     │ get_news        │ Response contains 2 injection        │
│           │            │                              │                 │ markers.                             │
│ UNCERTAIN │ response   │ data_exfiltration_probe      │ read_file       │ Tool errored on benign input;        │
│           │            │                              │                 │ cannot probe normal behavior.        │
│ UNCERTAIN │ response   │ response_injection_probe     │ read_file       │ Tool errored on benign input;        │
│           │            │                              │                 │ cannot probe normal behavior.        │
└───────────┴────────────┴──────────────────────────────┴─────────────────┴──────────────────────────────────────┘
```

`FAILURE` rows are hidden by default for readability; pass `--show-all` to see the clean checks too.

## How it works

A scan runs in three layers, cheapest first:

1. **Deterministic static attacks** scan the tool surface for known bad patterns. Zero cost, fast.
2. **LLM judge** (optional) reviews each finding and confirms or overrides. Cheap (gpt-4o-mini by default), capped per run.
3. **Adaptive LLM agent** (optional) probes each tool with multi-round reasoning, finding things the static patterns can't.

Five static attacks ship in v0.1, organized by the MCP pipeline stage they target:

| Attack | Stage | Active? | Catches |
|---|---|---|---|
| `description_prompt_injection` | metadata | passive | Tool descriptions carrying injection markers aimed at the calling LLM |
| `overreaching_parameters` | metadata | passive | Tools whose schema asks for `password`, `api_key`, `ssn`, etc. |
| `path_traversal_probe` | parameters | **active** | Tools that handle string parameters as filesystem paths (sends `../../etc/passwd`) |
| `response_injection_probe` | response | **active** | Tools whose response contains injection content aimed at the calling LLM |
| `data_exfiltration_probe` | response | **active** | Tools whose response coaxes the LLM to POST/send data to a sink |

The **adaptive agent** is the differentiator: given the tool surface, an LLM proposes payloads, observes responses, and iterates up to 3 rounds per tool. It catches social-engineering and unusual injection patterns the static heuristics can't enumerate ahead of time.

## Configure the LLM features (optional)

Both features are off by default; they auto-enable as soon as `OPENAI_API_KEY` is available, either as a shell export or in a `.env` file at the repo root.

```bash
# Option A: shell export
export OPENAI_API_KEY=sk-...

# Option B: .env file (gitignored; auto-loaded by the CLI)
echo 'OPENAI_API_KEY=sk-...' > .env

mcp-strike demo            # judge + agent both run
```

Useful flags:

| Flag | Effect |
|---|---|
| `--no-judge` / `--no-agent` | Force the corresponding feature off, even with a key set |
| `--judge` / `--agent` | Force on (errors gracefully if no key) |
| `--judge-model gpt-4o` | Override the default judge model (gpt-4o-mini) |
| `--agent-model gpt-4o` | Override the default agent model (gpt-4o-mini) |
| `--max-llm-calls 20` | Cap on real judge LLM calls per run |
| `--max-agent-calls 50` | Cap on real agent LLM calls per run |

A precedence note: a shell-exported variable always wins over `.env`. If you want `.env` to take precedence, `unset` the shell var first.

## Scan your own MCP server

```bash
# Stdio transport (the only one v0.1 supports; HTTP coming in a later release)
mcp-strike scan --command python --arg -m --arg your_mcp_server
mcp-strike scan --command /path/to/your-server --arg --port --arg 8080
```

`--arg` is repeatable; pass each argument separately so quoting works.

## JSON output for CI

```bash
mcp-strike demo --json --no-notice --output-file scan.json
```

Stable schema, suitable for CI pipelines. Top-level shape:

```json
{
  "summary": {
    "total": 29,
    "success": 5,
    "uncertain": 2,
    "failure": 22,
    "llm_calls_used": 7,        // null when judge didn't run
    "llm_calls_cap": 20,
    "agent_calls_used": null,   // null when agent didn't run
    "agent_calls_cap": null
  },
  "results": [
    {
      "attack_name": "description_prompt_injection",
      "stage": "metadata",
      "target_tool": "get_weather",
      "verdict": "success",
      "rationale": "...",
      "evidence": { "...": "..." },
      "judge": {
        "verdict": "success",
        "rationale": "...",
        "model": "gpt-4o-mini",
        "ran": true
      }
    }
  ]
}
```

Exit code is 0 even when findings exist — CI consumers decide what verdict counts as a build failure.

## Architecture at a glance

| Module | Role |
|---|---|
| `mcp_strike.client` | Stdio transport wrapper over the official `mcp` SDK |
| `mcp_strike.target` | Normalized `Target` adapter — what attacks consume |
| `mcp_strike.attacks` | `BaseAttack` ABC + decorator registry + the 5 concrete attacks |
| `mcp_strike.judge` | LLM-as-judge layer (NullJudge no-op + OpenAIJudge) |
| `mcp_strike.agent` | Adaptive LLM-driven attacker (Phase 3) |
| `mcp_strike.report` | Renderers: terminal (`rich`) + JSON |
| `mcp_strike.config` | `pydantic` config models + `.env` loader |
| `mcp_strike.cli` | `typer` entry point with `scan` / `list-attacks` / `demo` |
| `mcp_strike.demo_server` | Bundled vulnerable target with 6 planted vulnerabilities |

See [`docs/PLAN.md`](docs/PLAN.md) for the full architecture write-up and roadmap, and [`CLAUDE.md`](CLAUDE.md) for build discipline.

## Development

Requires Python 3.10+ and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/leo/mcp-strike
cd mcp-strike
uv sync --extra dev

uv run ruff check .
uv run pytest -v
uv run mcp-strike demo
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for project conventions, how to add a new attack, and how to plug in a different LLM provider.

## Status & roadmap

Currently **0.1.0 / alpha**. Phases 0–3 (foundation → core engine → judge → adaptive agent) are complete. See [`docs/PLAN.md`](docs/PLAN.md) for what's next.

## Responsible use

MCP-Strike is a defensive tool for testing MCP servers you own or are explicitly authorized to test. **It is not a weapon for attacking third-party infrastructure.** Running it against systems you don't control may be illegal in your jurisdiction and is not a supported use case. The CLI prints a responsible-use notice at startup; you can suppress it for scripting with `--no-notice` once you've internalized it.

If you find a vulnerability in someone else's server while using this tool, follow responsible disclosure — contact the maintainer privately before publishing details.

## License

MIT — see [`LICENSE`](LICENSE).

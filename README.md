# MCP-Strike

**Active, runtime adversarial testing for MCP servers: point it at your own server and find out what breaks.**

Most existing MCP scanners read tool descriptions and configs *statically*. MCP-Strike connects to a live [Model Context Protocol](https://modelcontextprotocol.io) server, runs a battery of real attacks against the actual tool surface, observes what comes back, and (optionally) uses an LLM-as-judge plus an LLM-driven adaptive agent to score each finding.

The wedge: a usable, *active*, single-developer tool for the dev who builds their own MCP server and just wants a "point it at my server and tell me what breaks" answer. Enterprise vendors aim at security teams; academic benchmarks produce papers; this is for you.

## Quickstart

```bash
pip install mcp-strike      # or: uvx mcp-strike demo
mcp-strike demo
```

That's it. `demo` spins up a bundled deliberately-vulnerable MCP server, scans it, and prints a colorized report. No keys required (the LLM features auto-enable only if you set `OPENAI_API_KEY`).

## What you get

A typical `mcp-strike demo --no-judge --no-agent` run:

```
╭────────────────────── Responsible use ──────────────────────╮
│ MCP-Strike is a defensive tool for testing MCP servers you  │
│ own. Running it against systems you don't control may be    │
│ illegal in your jurisdiction. See the "Responsible use"     │
│ section of this README for the full note.                   │
╰─────────────────────────────────────────────────────────────╯

Scan summary: 29 check(s) ran. 5 SUCCESS, 2 UNCERTAIN, 22 FAILURE

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

The judge and agent are off by default; they auto-enable as soon as `OPENAI_API_KEY` is available, either as a shell export or in a `.env` file at the repo root.

```bash
# Option A: shell export
export OPENAI_API_KEY=sk-...

# Option B: .env file (gitignored; auto-loaded by the CLI)
echo 'OPENAI_API_KEY=sk-...' > .env

mcp-strike demo            # judge + agent both run
```

A precedence note: a shell-exported variable always wins over `.env`. If you want `.env` to take precedence, `unset` the shell var first.

## All CLI flags

Run `mcp-strike --help`, `mcp-strike scan --help`, or `mcp-strike demo --help` for the full per-command listing. The most commonly used flags:

**Global**

| Flag | Effect |
|---|---|
| `--version` / `-V` | Print the installed version and exit. |

**Scan shape** (apply to `scan` and `demo`)

| Flag | Effect |
|---|---|
| `--only NAME` | Run only the named attack (repeatable). Recognizes the special name `adaptive_agent`. |
| `--call-timeout SECONDS` | Per-MCP-call timeout (default 30). A buggy or malicious server can't block the scan beyond this. |
| `--show-all` | Include FAILURE rows in the terminal report (hidden by default). |
| `--notice` / `--no-notice` | Print the responsible-use notice at startup (default on, terminal mode only). |
| `--json` | Emit JSON to stdout instead of a terminal table. Suppresses the notice. |
| `--output-file PATH` | Write the JSON report to a file. Implies `--json`. |

**LLM judge**

| Flag | Effect |
|---|---|
| `--judge` / `--no-judge` | Force the judge on/off. Default: auto, enabled iff `OPENAI_API_KEY` is set. |
| `--judge-model NAME` | Override the default judge model (`gpt-4o-mini`). |
| `--max-llm-calls N` | Cap on real judge LLM calls per run (default 20). |

**Adaptive agent**

| Flag | Effect |
|---|---|
| `--agent` / `--no-agent` | Force the agent on/off. Default: auto, enabled iff `OPENAI_API_KEY` is set. |
| `--agent-model NAME` | Override the default agent model (`gpt-4o-mini`). |
| `--agent-max-rounds N` | Per-tool round cap for the agent (default 3). |
| `--max-agent-calls N` | Cap on real agent LLM calls per run (default 50). |

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

Exit code is 0 even when findings exist; CI consumers decide what verdict counts as a build failure.

## Architecture at a glance

| Module | Role |
|---|---|
| `mcp_strike.client` | Stdio transport wrapper over the official `mcp` SDK |
| `mcp_strike.target` | Normalized `Target` adapter (what attacks consume) |
| `mcp_strike.attacks` | `BaseAttack` ABC + decorator registry + the 5 concrete attacks |
| `mcp_strike.judge` | LLM-as-judge layer (NullJudge no-op + OpenAIJudge) |
| `mcp_strike.agent` | Adaptive LLM-driven attacker |
| `mcp_strike.report` | Renderers: terminal (`rich`) + JSON |
| `mcp_strike.config` | `pydantic` config models + `.env` loader |
| `mcp_strike.cli` | `typer` entry point with `scan` / `list-attacks` / `demo` |
| `mcp_strike.demo_server` | Bundled vulnerable target with 6 planted vulnerabilities |

See [`ROADMAP.md`](ROADMAP.md) for what's shipped and what's next.

## Development

Requires Python 3.10+ and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/LeoMartinezTAMUK/mcp-strike.git
cd mcp-strike
uv sync --extra dev

uv run ruff check .                # lint
uv run mypy src/mcp_strike         # type-check
uv run pytest -v --cov             # tests + coverage report
uv run mcp-strike demo             # eyeball the scan output
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for project conventions, how to add a new attack, and how to plug in a different LLM provider.

## Status & roadmap

Currently **0.1.0 / alpha**. CI gates on `ruff` + `mypy` + `pytest` across Python 3.10 through 3.13; production source has ~90% line coverage. See [`ROADMAP.md`](ROADMAP.md) for what's next.

## Responsible use

MCP-Strike is a defensive tool for testing MCP servers you own or are explicitly authorized to test. **It is not a weapon for attacking third-party infrastructure.** Running it against systems you don't control may be illegal in your jurisdiction and is not a supported use case. The CLI prints a responsible-use notice at startup; you can suppress it for scripting with `--no-notice` once you've internalized it.

If you find a vulnerability in someone else's server while using this tool, follow responsible disclosure: contact the operator of that server privately before publishing details.

To report a security issue in MCP-Strike itself (not in a third-party server), see [`SECURITY.md`](SECURITY.md).

## License

MIT. See [`LICENSE`](LICENSE).

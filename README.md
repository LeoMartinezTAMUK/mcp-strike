# MCP-Strike

> **Status:** Pre-alpha. Phase 0 (foundation) only. Not yet usable as a CLI.

Active, runtime adversarial testing for [Model Context Protocol](https://modelcontextprotocol.io) servers — point it at an MCP server you own and find out what breaks.

Most existing MCP scanners read tool descriptions and configs *statically*. MCP-Strike connects to a live server, runs a battery of real attacks against the actual tool surface, observes what happens, and (in later phases) uses an LLM-as-judge to score each attempt.

## Responsible use

**MCP-Strike is a defensive tool for testing MCP servers you own or are explicitly authorized to test.** It is not a weapon for attacking third-party infrastructure. Running it against systems you don't control may be illegal in your jurisdiction and is not a supported use case. A responsible-use notice will print at CLI startup once the CLI lands (Phase 1+).

## Project status

See [`docs/PLAN.md`](docs/PLAN.md) for the full plan and [`CLAUDE.md`](CLAUDE.md) for build discipline. The roadmap is phased; each phase is independently shippable.

Currently shipped (Phase 0 + Phase 1):

- Project scaffolding (`uv` + `pyproject.toml`, `ruff`, `pytest`, GitHub Actions).
- Stdio MCP client + a normalized `Target` adapter.
- Deliberately-vulnerable demo MCP server with three planted vulnerabilities (description prompt injection, path traversal, overreaching credential params).
- A `BaseAttack` abstract class with a decorator-based registry.
- Three working attack modules with deterministic-heuristic scoring: `description_prompt_injection`, `overreaching_parameters`, `path_traversal_probe`.
- A `rich` terminal report renderer.
- A `typer` CLI with `scan`, `list-attacks`, and `demo` subcommands.

Not yet built: the LLM-as-judge, the adaptive red-team agent, JSON / HTML report output. Those land in Phases 2–4.

## Try it

After `uv sync --extra dev`:

```bash
uv run mcp-strike list-attacks     # show every registered attack
uv run mcp-strike demo             # scan the bundled vulnerable demo server
uv run mcp-strike scan --command python --arg -m --arg your_mcp_server
uv run mcp-strike demo --json      # machine-readable JSON report
```

To enable the LLM-as-judge (Phase 2), set `OPENAI_API_KEY` in your shell or in a `.env` file at the repo root (auto-loaded by the CLI):

```bash
# Either:
export OPENAI_API_KEY=sk-...
# Or write to .env (gitignored):
echo "OPENAI_API_KEY=sk-..." > .env

uv run mcp-strike demo             # judge runs automatically (gpt-4o-mini)
```

## Development setup

Requires Python 3.10+ and [`uv`](https://docs.astral.sh/uv/).

```bash
# Install runtime + dev dependencies into a local .venv
uv sync --extra dev

# Lint
uv run ruff check .

# Tests (includes the demo-server smoke test)
uv run pytest
```

## License

MIT — see [`LICENSE`](LICENSE).

# MCP-Strike Roadmap

What's shipped, what's next, and what's explicitly out of scope for v0.1. This document is intentionally short; the source of truth for *how* features work is the README and the code itself.

## Current status

**v0.1.0 / alpha.** The scanner is feature-complete for the v1 deliverable: connects to any MCP server you own over stdio, runs a battery of real attacks across all three pipeline stages, optionally augments findings with an LLM judge and an LLM-driven adaptive agent, and renders results to a colorized terminal table or a stable JSON document.

- **31 source modules**, ~830 lines of production code.
- **97 tests**, ~96% line coverage on production source (excludes the demo
  server, which runs as a subprocess and so can't be measured in-process).
- **CI gates on `ruff` + `mypy` + `pytest`** across Python 3.10, 3.11, 3.12, 3.13, plus a build-and-install smoke job that exercises the wheel end-to-end.
- **Bundled vulnerable demo server** with 6 planted vulnerabilities covering every attack class, so a stranger can validate the tool in 60 seconds.

## What's shipped

### Attacks (5 modules across 3 pipeline stages)

| Stage | Module | Active? | Catches |
|---|---|---|---|
| Metadata | `description_prompt_injection` | passive | Injection markers planted in tool descriptions |
| Metadata | `overreaching_parameters` | passive | Tool schemas that ask for credentials / PII |
| Parameters | `path_traversal_probe` | **active** | Tools that handle string params as filesystem paths |
| Response | `response_injection_probe` | **active** | Tool responses carrying injection content aimed at the calling LLM |
| Response | `data_exfiltration_probe` | **active** | Tool responses coaxing the LLM to POST/send data to a sink |

### LLM features (optional, opt-in via `OPENAI_API_KEY`)

- **Judge.** Reviews each non-FAILURE finding, confirms or overrides. Default model `gpt-4o-mini`. Per-run call cap.
- **Adaptive agent.** Given the tool surface, proposes payloads, observes responses, iterates up to 3 rounds per tool. Catches social-engineering and novel injection patterns the static checks can't enumerate.

### Output

- Colorized terminal report via Rich (sorted by verdict severity).
- Stable JSON schema for CI pipelines; full schema documented in the README's "JSON output for CI" section.

### Infrastructure

- `pip install` / `uvx` distribution (PyPI publish pending).
- `mcp-strike demo` one-command experience.
- `mcp-strike scan --command ... --arg ...` for your own MCP server.
- Per-MCP-call timeout, per-LLM-call timeout, per-run LLM-call caps. Cost and stability bounded.
- `.env` auto-loading from the working directory.

## Out of scope for v0.1

These are deliberately deferred: not bugs, not gaps, just product decisions:

- **Hosted SaaS / dashboards / fleet monitoring.** v0.1 is strictly a local CLI.
- **Scanning third-party servers you don't own.** The tool is framed and documented as a defensive scanner for your own infrastructure. See "Responsible use" in the README.
- **Runtime production guardrails.** Different product.
- **Non-MCP agent / tool protocols.**

## What's next

### Likely for v0.2

Real features that aren't in v0.1 yet:

- **HTTP / SSE transport.** v0.1 supports stdio only. Most self-hosted MCP servers today are stdio, but HTTP is increasingly common, particularly for remote servers. Add `open_http_target(url)` + `--transport http --url ...` to the CLI.
- **Scan diff.** `mcp-strike diff baseline.json current.json`: show new SUCCESS rows and verdict flips. Useful for CI regression tracking against a known-good baseline.
- **Custom attack patterns from config.** `--patterns config.yaml` to merge user-defined injection markers and exfiltration regexes into the heuristic lists, without forking the project.

### Stretch goals (later versions)

- Cross-server toxic-flow analysis (one tool's output triggering another tool's call).
- GitHub Actions integration for CI gating.
- HTML report renderer (the same data, prettier).
- A shareable "MCP server security badge" derived from a scan.
- Pluggable support for additional agent/tool protocols beyond MCP. The attack engine and judge are deliberately protocol-agnostic underneath.

A hosted continuous-scanning service is a *separate, later* product, deliberately not a goal of this open-source project.

## Get involved

- Bug reports and feature requests: open an issue.
- Pull requests: see [`CONTRIBUTING.md`](CONTRIBUTING.md) for project conventions and how to add a new attack.
- Security issues in MCP-Strike itself: see [`SECURITY.md`](SECURITY.md).
- Found a real vulnerability in someone's MCP server while using this tool? Follow responsible disclosure: contact them privately first.

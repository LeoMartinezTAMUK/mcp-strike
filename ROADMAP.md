# MCP-Strike — Roadmap

What's shipped, what's next, and what's explicitly out of scope for v0.1. This document is intentionally short — the source of truth for *how* features work is the README and the code itself.

## Current status

**v0.1.0 / alpha.** The scanner is feature-complete for the v1 deliverable: connects to any MCP server you own over stdio, runs a battery of real attacks across all three pipeline stages, optionally augments findings with an LLM judge and an LLM-driven adaptive agent, and renders results to a colorized terminal table or a stable JSON document.

- **31 source modules**, ~770 lines of production code.
- **83 tests**, ~90% line coverage on production source.
- **CI gates on `ruff` + `mypy` + `pytest`** across Python 3.10, 3.11, 3.12, 3.13, plus a build-and-install smoke job that exercises the wheel end-to-end.
- **Bundled vulnerable demo server** with 6 planted vulnerabilities covering every attack class — so a stranger can validate the tool in 60 seconds.

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
- Stable JSON schema for CI pipelines — full schema documented in the README's "JSON output for CI" section.

### Infrastructure

- `pip install` / `uvx` distribution (PyPI publish pending).
- `mcp-strike demo` one-command experience.
- `mcp-strike scan --command ... --arg ...` for your own MCP server.
- Per-MCP-call timeout, per-LLM-call timeout, per-run LLM-call caps — cost and stability bounded.
- `.env` auto-loading from the working directory.

## Out of scope for v0.1

These are deliberately deferred — not bugs, not gaps, just product decisions:

- **Hosted SaaS / dashboards / fleet monitoring.** v0.1 is strictly a local CLI.
- **Scanning third-party servers you don't own.** The tool is framed and documented as a defensive scanner for your own infrastructure. See "Responsible use" in the README.
- **Runtime production guardrails.** Different product.
- **Non-MCP agent / tool protocols.**

## What's next

### Pre-launch (Phase 5)

The codebase is ready to publish. What remains is launch work, not engineering:

- [ ] Tag `v0.1.0` on GitHub.
- [ ] Publish to PyPI (`uv build && uv publish`).
- [ ] Write a launch post explaining the *active testing* wedge (why static scanners miss the dynamic vulnerabilities this tool catches).
- [ ] Post to MCP / AI-security communities (LinkedIn, Hacker News, MCP Discord, relevant subreddits).
- [ ] Open the public issue tracker for feedback.

### Likely for v0.2

Items that came up during the v0.1 audit but were explicitly deferred because they're real features, not polish:

- **HTTP / SSE transport.** v0.1 supports stdio only. Most self-hosted MCP servers today are stdio, but HTTP is increasingly common — particularly for remote servers. Add `open_http_target(url)` + `--transport http --url ...` to the CLI.
- **Scan diff.** `mcp-strike diff baseline.json current.json` — show new SUCCESS rows and verdict flips. Useful for CI regression tracking against a known-good baseline.
- **Custom attack patterns from config.** `--patterns config.yaml` to merge user-defined injection markers and exfiltration regexes into the heuristic lists, without forking the project.

### Stretch goals (v0.x or later)

Listed in the original plan as "post-v1 / future":

- Cross-server toxic-flow analysis (one tool's output triggering another tool's call).
- GitHub Actions integration for CI gating.
- HTML report renderer (the same data, prettier).
- A shareable "MCP server security badge" derived from a scan.
- Pluggable support for additional agent/tool protocols beyond MCP — the attack engine and judge are deliberately protocol-agnostic underneath.

A hosted continuous-scanning service is a *separate, later* product — deliberately not a goal of this open-source project.

## How phases work

The project is structured as small, independently-shippable phases. Each phase has a single deliverable. Phases 0–4 are complete:

| Phase | Theme | Status |
|---|---|---|
| 0 | Foundation: scaffolding + stdio client + vulnerable demo server | ✅ |
| 1 | Core engine: BaseAttack registry + 3 static attacks + terminal report | ✅ |
| 2 | LLM judge + Stage-3 attacks (response injection, exfiltration) + JSON output | ✅ |
| 3 | Adaptive LLM agent | ✅ |
| 4 | Polish & packaging: package the demo server, README, mypy/coverage, CI matrix | ✅ |
| 5 | Launch: tag, publish, post | ⏳ |

After v0.1.0, work happens against versioned milestones rather than phase numbers.

## Get involved

- Bug reports and feature requests: the issue tracker (after launch).
- Pull requests: see [`CONTRIBUTING.md`](CONTRIBUTING.md) for project conventions and how to add a new attack.
- Found a real vulnerability in someone's MCP server while using this tool? Follow responsible disclosure — contact them privately first.

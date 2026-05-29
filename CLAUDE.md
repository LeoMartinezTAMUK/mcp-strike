# CLAUDE.md — `MCP-Strike`

Project context for Claude Code. **Read this fully at the start of every session.**

## What this is
An open-source Python CLI that does **active, runtime adversarial testing** of MCP servers the user owns. Full plan: **`docs/PLAN.md`** — always defer to it for scope and architecture.

## CURRENT PHASE
**Phases 0–2: COMPLETE.** Next up: **Phase 3 — Adaptive agent + richer reporting** (not started; do not begin without explicit go-ahead).
Build ONLY what the current phase requires. Do **not** implement the adaptive agent or features beyond Phase 3's scope until the phase that introduces them (see PLAN.md §10). If I ask for something from a later phase, stop and confirm with me first.
> Update this line as each phase completes (Phase 3, Phase 4, …).

## Build discipline
- One phase at a time, in order.
- Before writing significant code, propose a short step list and **wait for my OK**.
- Keep changes small and reviewable. Explain any non-obvious decision.
- I, the author, must understand **every line** — clarity over cleverness. No dense one-liners, no magic, no undocumented hacks.

## Tech constraints
- Python 3.10+, **type hints on all public functions**.
- Use the **official MCP Python SDK** for the protocol — do not hand-roll MCP. Verify the exact package name and import path from current docs or by installing; **do not guess**.
- CLI: `typer` + `rich`. HTTP/API: `httpx`. Models/config: `pydantic` v2. Tests: `pytest`. Lint/format: `ruff`. Env + packaging: `uv` with `pyproject.toml`.
- `src/` layout: code lives under `src/mcp_strike/`.
- No new heavy dependencies without asking me first.

## Conventions
- **Secrets/API keys: environment variables only.** Never hardcode, never commit. `.env` is gitignored; maintain a `.env.example`.
- Every module gets tests. `ruff` must pass and `pytest` must pass before a step is "done."
- Commit messages: concise, imperative ("add stdio client", not "added stuff").

## Cost discipline
- LLM judge/agent calls cost money. Default to a cheap model, add per-run call caps, and prefer deterministic checks before calling an LLM.

## Safety / ethics
- This tool tests MCP servers **the user owns** — it is not for attacking third-party infrastructure. Keep a responsible-use note in the README and at CLI startup. Do not add features whose primary purpose is attacking systems the user doesn't control.

## Definition of done (per step)
Typed + `ruff`-clean + tests passing + I've reviewed and understood it.

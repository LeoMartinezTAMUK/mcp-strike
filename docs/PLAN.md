# Project Plan — `MCP-Strike`

## 1. Summary

`MCP-Strike` is an open-source Python CLI that performs **active, runtime adversarial testing** of Model Context Protocol (MCP) servers. Unlike the existing scanners — which mostly read tool descriptions and configs *statically* — this tool **connects to a running MCP server, executes a battery of live attacks against the real tool surface, observes the actual behavior, and uses an LLM-as-judge to score whether each attack succeeded.** It then produces a developer-friendly report.

The target user is the **individual developer who builds/runs their own MCP server** and wants a dead-simple "point it at my server and tell me what breaks" tool. Enterprise vendors (Cisco, Snyk, Enkrypt) aim at security teams and fleet monitoring; academic benchmarks produce papers no normal engineer can run. The gap is a usable, active, single-developer tool — that's the wedge.

## 2. Problem & Positioning

- **Static scanners miss the dynamic stuff.** Indirect/response injection, toxic flows, and parameter-handling bugs only show up when you actually *run* attacks against a live server. The vendors themselves admit response-channel injection is "very difficult for a scanner alone."
- **The attack knowledge is public.** Open taxonomies (MSB, MCPSecBench, MCP-SafetyBench, OWASP Agentic Top 10) define the attack classes. The contribution here is not novel attacks — it's **active execution + excellent developer UX** for a segment nobody is serving well.
- **Why this fits the author:** prior benchmark-building experience (ROSE-Bench), adversarial LLM evaluation (red-teaming day job), and agent construction. ~80% of what gets built here (prompt injection, indirect injection, LLM-as-judge, an autonomous attack agent) is general adversarial-AI-security skill that transfers to any role; MCP is only the delivery surface.

## 3. Objectives

**Primary (locked-in regardless of business outcome):**
- Ship a public, polished, *used* open-source tool.
- Learn adversarial AI security and MCP deeply enough to explain every line in interviews.

**Secondary (the swing):**
- Become the tool MCP developers reach for; if traction appears, add a hosted layer (CI integration, continuous scans, team dashboards) as a *separate, later* product.

**Concrete v1 success criteria:**
- Runs against a real MCP server over both stdio and HTTP transports.
- ≥ 8 working attack modules across ≥ 3 pipeline stages.
- LLM-as-judge scoring with a clear pass/fail/uncertain verdict per attack.
- Clean terminal report + machine-readable JSON output.
- Ships a deliberately-vulnerable demo server so anyone can try it in 60 seconds.
- Published to PyPI, MIT/Apache-2.0 licensed, CI green, README + launch blog post.

## 4. Scope

**In scope (v1):**
- Connect to MCP servers via the official MCP Python SDK (stdio + HTTP/SSE transports).
- Discovery: enumerate tools, resources, and prompts.
- Pluggable attack engine (registry of attack modules).
- LLM-as-judge scoring module (model-agnostic).
- Optional **adaptive red-team agent** mode (an LLM loop that mutates/crafts attacks) — high learning value and the core differentiator.
- Reporting: `rich` terminal output + JSON; HTML as a stretch.
- Config via file + environment variables (never hardcode keys).
- Bundled deliberately-vulnerable demo MCP server for testing/onboarding.

**Out of scope (v1) — explicitly deferred:**
- Hosted SaaS, dashboards, fleet/continuous monitoring.
- Scanning arbitrary third-party servers the user does **not** own (abuse/legal surface — later phase with safeguards).
- Runtime production guardrails/enforcement (a *different* product; don't conflate).
- Non-MCP agent frameworks.

## 5. Key Design Assumption

**v1 tests a server the user owns / runs themselves** (a cooperative target). The CLI is a pentest tool for your own assets, like running ZAP against your own app. All docs and the README state this explicitly, with a responsible-use note. This keeps v1 simple and avoids building an attack weapon aimed at others.

## 6. Architecture

Component-based, each piece independently testable:

- **`client/`** — MCP connection layer. Thin wrapper over the official MCP Python SDK. Handles stdio + HTTP transports, session lifecycle, and discovery (list tools/resources/prompts).
- **`target/`** — Target adapter. Normalizes "the server under test" so attacks don't care about transport details.
- **`attacks/`** — Attack modules. A `BaseAttack` abstract class + a registry/decorator so new attacks are drop-in. Each attack: `prepare()`, `execute(target)`, returns a structured `AttackResult` (request sent, response observed, metadata).
- **`judge/`** — Scoring. Default = LLM-as-judge (pluggable model via env-configured provider); plus cheap deterministic heuristics where possible to save API calls. Returns `success | failure | uncertain` + rationale.
- **`agent/`** — (Phase 3) Adaptive attacker. An LLM loop that, given a tool surface, proposes and mutates attacks, observes results, and iterates. This is where the "more than MCP" learning lives.
- **`report/`** — Renderers: terminal (`rich`), JSON, HTML (stretch).
- **`config/`** — `pydantic` models for target config + run settings; keys from env only.
- **`cli.py`** — `typer` app. Commands: `scan`, `list-attacks`, `demo` (spins up the vulnerable server and attacks it), `report`.
- **`mcp_strike/demo_server/`** — A small, intentionally-vulnerable MCP server used for development, tests, and user onboarding. Bundled inside the installable package so `mcp-strike demo` works out of the box after `pip install`.

## 7. Attack Taxonomy for v1

Organized by MCP pipeline stage (planning → invocation → response handling). Implement the **bold** ones first; the rest are v1 stretch / v1.1.

**Stage 1 — Tool signature / metadata**
- **Prompt injection in tool descriptions** (instructions hidden in a tool's description aimed at the calling LLM)
- **Tool poisoning** (description that quietly redirects behavior)
- Name collision / tool shadowing (a tool that impersonates another)

**Stage 2 — Tool parameters / invocation**
- **Out-of-scope / overreaching parameter requests** (tool asks for data it shouldn't need)
- **Injection passthrough** (params flow unsanitized into shell/SQL/path — command & path traversal probes)
- Parameter pollution / type confusion

**Stage 3 — Tool responses / response handling**
- **Indirect / response injection** (malicious instructions in a tool's *returned content* aimed at the LLM) — the flagship dynamic attack
- **Data-exfiltration patterns** (tool response tries to induce sending data to an external sink)

**Cross-cutting (v1 stretch / v1.1)**
- Toxic flows / confused deputy across multiple tools
- Auth/transport weaknesses (missing auth, sensitive data exposure)

## 8. Tech Stack (Python-first)

- **Language:** Python 3.10+ (matches Ubuntu 22.04 default; type hints throughout).
- **MCP protocol:** official MCP Python SDK (`mcp` on PyPI) — do **not** hand-roll the protocol.
- **CLI:** `typer` (type-hint driven) + `rich` (terminal rendering).
- **HTTP / API:** `httpx`.
- **Data models / config:** `pydantic` v2.
- **LLM judge & agent:** `anthropic` and/or `openai` SDK, provider selectable via config. Default to a cheap, fast model for the judge to control cost.
- **Testing:** `pytest` (+ the bundled vulnerable demo server as a fixture).
- **Lint/format:** `ruff`.
- **Env/packaging:** `uv` (fast, modern) with `pyproject.toml`; publishable to PyPI.
- **CI:** GitHub Actions (lint + test on push).
- **Docs:** README first; MkDocs + GitHub Pages as a stretch.

## 9. Suggested Repository Layout

```
mcp-strike/
├── src/mcp_strike/
│   ├── client/
│   ├── target/
│   ├── attacks/
│   ├── judge/
│   ├── agent/
│   ├── report/
│   ├── config/
│   ├── demo_server/    # bundled in the wheel; runs the vulnerable demo
│   └── cli.py
├── tests/
├── docs/
│   └── PLAN.md          # this file
├── CLAUDE.md            # house rules for Claude Code
├── pyproject.toml
├── README.md
└── LICENSE
```

## 10. Roadmap / Milestones (~6 weeks, part-time)

**Phase 0 — Foundation (a few days)**
- Repo init, `uv` env, `pyproject.toml`, `ruff`, `pytest`, GitHub Actions skeleton, `CLAUDE.md`.
- "Hello MCP": connect to a server with the SDK and list its tools.
- Build the deliberately-vulnerable demo server.
- *Deliverable:* you can connect to the demo server and enumerate its tool surface.

**Phase 1 — Core engine (weeks 1–2)**
- `BaseAttack` interface + registry; target adapter; 3–4 Stage-1/Stage-2 attacks; basic terminal report. Scoring via simple heuristics for now.
- *Deliverable:* `mcp-strike scan` runs real attacks against the demo server and prints findings.

**Phase 2 — Judge + dynamic attacks (weeks 2–3)**
- LLM-as-judge module; add response-injection + exfiltration attacks (the differentiators); JSON output.
- *Deliverable:* attacks scored with rationale; JSON suitable for CI.

**Phase 3 — Adaptive agent + reporting (week 4)**
- Adaptive attacker loop; richer reporting (HTML stretch).
- *Deliverable:* `--adaptive` mode that discovers issues the static modules miss.

**Phase 4 — Polish & package (week 5)**
- Docs, README with GIF/demo, `--demo` one-command experience, packaging, PyPI publish, responsible-use notice.
- *Deliverable:* `pip install mcp-strike` / `uvx mcp-strike` works for a stranger.

**Phase 5 — Launch (week 6)**
- Launch blog post (the "why active testing" angle), post to MCP/AI-security communities, tag `v0.1.0`, open the issue tracker.
- *Deliverable:* public release + feedback loop.

> Note: completing **Phases 0–2 alone** already yields a credible, shippable résumé project. Everything after is upside.

## 11. Deployment & Distribution

- **v1:** local CLI distributed via PyPI (`pip install` / `uvx`). Public GitHub repo, permissive license (MIT or Apache-2.0). CI via GitHub Actions. Docs via README (+ optional GitHub Pages).
- **Future (only if traction):** a hosted service for CI/CD integration, continuous scanning, drift tracking, and team dashboards — built as a separate layer on top of the OSS core. This is where any revenue lives; it is deliberately **not** part of v1.

## 12. Constraints

- **Python-first** — author must fully understand every component to ship and present it; favor readability over cleverness, type everything, document the non-obvious.
- **Low cost** — local CLI; only spend is LLM API calls for judge/agent. Use a cheap judge model, cache where possible, and add per-run call caps. Expect single/low-double-digit dollars/month during development.
- **Part-time bandwidth** — author has a new full-time job; phase-gating exists to guarantee a shippable artifact even if later phases slip.
- **Solo maintainer** — scope must stay narrow; resist turning this into a general platform.

## 13. Risks & Mitigations

- **Incumbents add a module** → Stay deeper on *active* testing + developer UX, the segment they ignore. Be public early.
- **Scope creep** → Strict phase gates; "out of scope" list is load-bearing.
- **API cost surprises** → Cheap default judge model, deterministic pre-filters, per-run caps, caching.
- **Abuse/ethics** → Owned-target framing, prominent responsible-use notice, no features whose primary purpose is attacking others' infrastructure.
- **Shipping risk with a day job** → Phases 0–2 are independently shippable; treat them as the real MVP.
- **MCP market plateau** → Keep the attack engine and judge protocol-agnostic underneath so the core can extend to other agent/tool protocols later without a rewrite.

## 14. Ethics & Safety Posture

This is a defensive tool for testing systems you own. The README and CLI startup notice state this. No bundled capability is designed to compromise third-party infrastructure. Findings are framed for remediation, with a responsible-disclosure note for anyone who tests servers they don't control.

## 15. Future / Stretch (post-v1)

- Cross-server toxic-flow analysis.
- CI/CD GitHub Action.
- Hosted continuous-scanning service + dashboards (the business layer).
- Pluggable support for additional agent/tool protocols.
- A public "how robust is this server" report format that could become a shareable badge.

## 16. References (public attack taxonomies to draw from)

- MSB — MCP Security Bench (12-attack taxonomy; runs real tools)
- MCPSecBench (17 attacks across user/host/transport/server layers)
- MCP-SafetyBench (real-world servers, multi-step/multi-server)
- OWASP Agentic Top 10
- Vendor write-ups: Cisco MCP Scanner, Snyk agent-scan, Invariant MCP-Scan (study for coverage gaps, not to copy)

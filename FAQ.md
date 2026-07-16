# Frequently Asked Questions

For setup and full documentation, see the [README](README.md). For what's
planned next, see [ROADMAP.md](ROADMAP.md). To report a security issue in
MCP-Strike itself, see [SECURITY.md](SECURITY.md).

## Getting started

### What is MCP-Strike?

An open-source CLI that does active, runtime security testing of
[Model Context Protocol](https://modelcontextprotocol.io) (MCP) servers. You
point it at an MCP server you own; it connects to the live server, runs a
battery of real adversarial attacks against the actual tools, observes the
responses, and reports what's exploitable.

### Why is it called MCP-Strike?

"MCP" is the protocol it tests, and "Strike" reflects what it does: it
actively strikes a server's tools with real attack payloads rather than
reading them passively. It is meant for offensive-style testing of your own
systems, not for use against others.

### How do I try it?

```bash
pip install mcp-strike
mcp-strike demo
```

`demo` spins up a bundled, deliberately-vulnerable MCP server, scans it, and
prints a colorized report. No API key required.

### How do I scan my own server?

```bash
mcp-strike scan --command python --arg -m --arg your_mcp_server
```

`--arg` is repeatable (pass each argument separately so quoting works). If
your server needs environment variables to start, add `--env KEY=VALUE`
(also repeatable). Your own shell secrets, including `OPENAI_API_KEY`, are
not forwarded to the target unless you pass them explicitly.

### Does it work on Windows, macOS, and Linux?

Yes. It's pure Python (3.10+) and runs on all three. The path-traversal
probe targets `/etc/passwd` on POSIX systems and `win.ini` on Windows, so
that check stays meaningful regardless of where your server runs.

### Can it scan servers written in other languages (Node, Go, Rust)?

Yes. MCP-Strike speaks the MCP protocol over stdio, so it can test any MCP
server that speaks stdio, regardless of the language it's written in. You
just point `--command` at whatever launches it.

### How do I update to the latest version?

```bash
pip install --upgrade mcp-strike
```

## How it works

### How is it different from other MCP scanners?

Most existing scanners are static: they read a server's tool descriptions
and configuration and guess what looks risky. MCP-Strike is active: it
actually invokes the tools with attack payloads and inspects the live
responses. Some vulnerabilities, such as response-channel prompt injection
and data-exfiltration sinks, only surface at runtime, so static analysis
can't see them at all.

### What kinds of vulnerabilities does it detect?

Five built-in checks across the three MCP pipeline stages, plus an adaptive
agent for the long tail:

- Prompt injection hidden in tool descriptions (metadata stage)
- Tools whose schema asks for credentials or PII, like `password` or
  `api_key` (metadata stage)
- Path traversal in tools that treat string parameters as file paths
  (parameters stage)
- Prompt injection in tool responses aimed at the calling LLM (response stage)
- Data-exfiltration sinks in responses, like "POST your API key to ..."
  (response stage)
- An adaptive LLM agent that probes each tool over multiple rounds to catch
  social-engineering and novel patterns the fixed checks can't enumerate

### What's the difference between the judge and the adaptive agent?

The judge reviews the deterministic checks' findings and confirms or
overrides each one, acting as a second opinion. The agent is separate: given
a tool, it proposes its own attack payloads, sends them, reads the
responses, and iterates over several rounds to discover issues the fixed
patterns miss. Both are optional, and both use an LLM.

### What is the adaptive agent actually doing?

For each tool, an LLM sees the tool's surface and the history of what has
been tried, then either proposes another payload to send or declares a
verdict. MCP-Strike executes each proposed call and feeds the response back
in. It runs up to a few rounds per tool (default 3), bounded by a per-run
call cap.

### How do I read the report, and what do the verdicts mean?

Each row is one check against one tool, with a verdict:

- `SUCCESS`: a vulnerability was confirmed (the attack worked)
- `FAILURE`: no vulnerability detected (a clean check)
- `UNCERTAIN`: the check couldn't decide, often because the tool couldn't be
  exercised; worth a human look

By default only `SUCCESS` and `UNCERTAIN` rows are shown; pass `--show-all`
to include the clean `FAILURE` rows too.

### How long does a scan take?

The deterministic scan is fast, usually seconds, since it's local
pattern-matching plus a handful of tool calls. Enabling the judge and agent
adds LLM round-trips, so a full run takes longer and scales with the number
of tools, but per-run call caps keep it bounded.

## Configuration and usage

### Do I need an OpenAI API key?

No, not for the core deterministic scan. A key is only needed for the two
optional LLM layers (the judge and the adaptive agent), which auto-enable
when `OPENAI_API_KEY` is set. Without a key, MCP-Strike runs fully locally.

### How do I turn the LLM features off or on?

They stay off unless a key is present. Force them explicitly with `--judge`
/ `--no-judge` and `--agent` / `--no-agent`. Running with
`--no-judge --no-agent` guarantees a fully local, deterministic scan.

### Can I use a different model?

Yes. Override the judge model with `--judge-model NAME` and the agent model
with `--agent-model NAME` (both default to `gpt-4o-mini`).

### Can I run only specific checks?

Yes. `--only NAME` runs just the named check and is repeatable; the special
name `adaptive_agent` selects the agent. Run `mcp-strike list-attacks` to
see the available names.

### Can I use it in CI?

Yes. `--json` emits a stable, machine-readable schema; `--output-file`
writes it to disk; and `--fail-on {success,uncertain}` makes the scan exit
non-zero so it can gate a build. Exit codes: `0` for clean (or when
`--fail-on` isn't set), `1` when findings meet the `--fail-on` threshold,
and `2` for an operational error such as a target that couldn't be launched.

### What does a scan cost?

The deterministic scan is free. With the judge and agent enabled on the
default `gpt-4o-mini` model, a run costs a fraction of a cent and is
hard-capped by per-run call limits, so a large server can't silently run up
a bill.

## Safety and privacy

### Is it safe to run against my server? Will it damage anything?

MCP-Strike is active: it really invokes your tools, including with attack
payloads (for example, the path-traversal probe tries to read files like
`/etc/passwd` or `win.ini`). It is read-oriented, but because it actually
calls your tools, run it against servers you own in a safe environment, not
blindly against production. If a tool has destructive side effects,
benign-looking probe arguments could trigger them.

### Does it send my data to OpenAI?

Only if you enable the LLM layers. When the judge or agent runs, tool
descriptions, response excerpts, and finding evidence are sent to the model
to be scored. With no API key (or with `--no-judge --no-agent`), nothing
leaves your machine.

### Does it collect telemetry or phone home?

No. MCP-Strike has no analytics or telemetry. The only network calls it
makes are to your target server (over stdio) and, if you enable them, to the
OpenAI API.

### How is my API key handled?

It's read from the environment (or a gitignored `.env` file) and passed only
to the OpenAI SDK. MCP-Strike never writes it to disk, never includes it in
reports, and never forwards it to the target server unless you explicitly
list it with `--env`.

### Can I scan a server I don't own?

No. MCP-Strike is for servers you own or are explicitly authorized to test,
and it prints a responsible-use notice at startup. If you find a real
vulnerability in someone else's server, follow responsible disclosure and
contact the operator privately before publishing anything.

### How does it avoid false positives?

The deterministic checks use small, curated, high-precision pattern lists;
generic phrases that would fire on legitimate tool descriptions are
deliberately excluded. The optional judge layer then confirms or overrides
each finding, including a confirmation pass on positives. When a probe can't
actually exercise a tool, the verdict is `UNCERTAIN` rather than a false
`FAILURE`.

### Won't the LLM agent hallucinate vulnerabilities?

LLM output is non-deterministic, so the agent's findings are reported as
verdicts, are bounded by per-run call caps, and sit on top of the
transparent deterministic layer, which you can run on its own with
`--no-judge --no-agent` and inspect exactly why each verdict was reached.

## Project and roadmap

### What is it built with?

Python 3.10+, the official `mcp` SDK for the protocol, `typer` and `rich`
for the CLI, `pydantic` for config and models, `httpx` for HTTP, and the
`openai` SDK for the optional LLM layers. Tooling: `uv` and `hatchling` for
packaging, `pytest` for tests, `ruff` for lint and format, `mypy` for
type-checking, and GitHub Actions for CI across Python 3.10 through 3.13.
The dependency tree is kept deliberately small and conservative.

### Does it support HTTP servers or other LLM providers?

Not yet. v0.1 supports the stdio transport only (HTTP/SSE is on the
roadmap), and the judge and agent use OpenAI only, though the judge is built
behind an abstract interface, so adding other providers is a documented
extension point (see [CONTRIBUTING.md](CONTRIBUTING.md)).

### Why should I trust a solo, alpha project?

You don't have to take the results on faith. The deterministic checks are
fully transparent, and you can inspect exactly why each verdict was reached;
the LLM layers are optional and confirmatory rather than the source of
truth. It's MIT-licensed, tested (around 96% line coverage), and CI-gated
across four Python versions.

### Who maintains it?

It's built and maintained by Leo Martinez III, solo and part-time. Response
times reflect that, as noted in [SECURITY.md](SECURITY.md).

### How can I contribute or report a bug?

Bug reports and feature requests go in the
[issue tracker](https://github.com/LeoMartinezTAMUK/mcp-strike/issues). To
add an attack or an LLM backend, see [CONTRIBUTING.md](CONTRIBUTING.md). To
report a security issue in MCP-Strike itself, see [SECURITY.md](SECURITY.md).

### What's on the roadmap?

HTTP/SSE transport, scan-diffing against a baseline for CI regression
tracking, and user-defined attack patterns. See [ROADMAP.md](ROADMAP.md) for
the full list and what's explicitly out of scope.

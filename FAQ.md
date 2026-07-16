# Frequently Asked Questions

For setup and full documentation, see the [README](README.md). For what's
planned next, see [ROADMAP.md](ROADMAP.md). To report a security issue in
MCP-Strike itself, see [SECURITY.md](SECURITY.md).

## What is MCP-Strike?

An open-source CLI that does **active, runtime security testing** of
[Model Context Protocol](https://modelcontextprotocol.io) (MCP) servers. You
point it at an MCP server you own; it connects to the live server, runs a
battery of real adversarial attacks against the actual tools, observes the
responses, and reports what's exploitable.

## How is it different from other MCP scanners?

Most existing scanners are *static* — they read a server's tool descriptions
and configuration and guess what looks risky. MCP-Strike is *active*: it
actually invokes the tools with attack payloads and inspects the live
responses. Some vulnerabilities (response-channel prompt injection,
data-exfiltration sinks) only surface at runtime, so static analysis can't
see them at all.

## Who is it for?

The developer who builds their own MCP server and wants a quick "point it at
my server and tell me what breaks" answer. It's intentionally a lightweight,
single-developer CLI — not an enterprise platform or an academic benchmark.

## How do I try it?

```bash
pip install mcp-strike
mcp-strike demo
```

`demo` spins up a bundled, deliberately-vulnerable MCP server, scans it, and
prints a colorized report. No API key required.

## Do I need an OpenAI API key?

No — not for the core deterministic scan. A key is only needed for the two
optional LLM layers (the judge and the adaptive agent), which auto-enable
when `OPENAI_API_KEY` is set. Without a key, MCP-Strike runs fully locally.

## How do I scan my own server?

```bash
mcp-strike scan --command python --arg -m --arg your_mcp_server
```

`--arg` is repeatable (pass each argument separately so quoting works). If
your server needs environment variables to start, add `--env KEY=VALUE`
(also repeatable). Your own shell secrets — including `OPENAI_API_KEY` — are
not forwarded to the target unless you pass them explicitly.

## Is it safe to run against my server? Will it damage anything?

MCP-Strike is *active* — it really invokes your tools, including with attack
payloads (for example, the path-traversal probe tries to read files like
`/etc/passwd` or `win.ini`). It is read-oriented, but because it actually
calls your tools, run it against servers you own in a safe environment, not
blindly against production. If a tool has destructive side effects,
benign-looking probe arguments could trigger them.

## Does it send my data to OpenAI?

Only if you enable the LLM layers. When the judge or agent runs, tool
descriptions, response excerpts, and finding evidence are sent to the model
to be scored. With no API key (or with `--no-judge --no-agent`), nothing
leaves your machine.

## Can I scan a server I don't own?

No. MCP-Strike is for servers you own or are explicitly authorized to test,
and it prints a responsible-use notice at startup. If you find a real
vulnerability in someone else's server, follow responsible disclosure and
contact the operator privately before publishing anything.

## How does it avoid false positives?

The deterministic checks use small, curated, high-precision pattern lists —
generic phrases that would fire on legitimate tool descriptions are
deliberately excluded. The optional judge layer then confirms or overrides
each finding, including a confirmation pass on positives. When a probe can't
actually exercise a tool, the verdict is `UNCERTAIN` rather than a false
`FAILURE`.

## Won't the LLM agent hallucinate vulnerabilities?

LLM output is non-deterministic, so the agent's findings are reported as
verdicts, are bounded by per-run call caps, and sit on top of the
transparent deterministic layer — which you can run on its own with
`--no-judge --no-agent` and inspect exactly why each verdict was reached.

## What does a scan cost?

The deterministic scan is free. With the judge and agent enabled on the
default `gpt-4o-mini` model, a run costs a fraction of a cent and is
hard-capped by per-run call limits, so a large server can't silently run up
a bill.

## Can I use it in CI?

Yes. `--json` emits a stable, machine-readable schema; `--output-file`
writes it to disk; and `--fail-on {success,uncertain}` makes the scan exit
non-zero so it can gate a build. Exit codes: `0` = clean (or `--fail-on` not
set), `1` = findings met the `--fail-on` threshold, `2` = an operational
error (e.g. the target couldn't be launched).

## Does it support HTTP servers or other LLM providers?

Not yet. v0.1 supports the stdio transport only (HTTP/SSE is on the
roadmap), and the judge/agent use OpenAI only — though the judge is built
behind an abstract interface, so adding other providers is a documented
extension point (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## What is it built with?

Python 3.10+, the official `mcp` SDK for the protocol, `typer` + `rich` for
the CLI, `pydantic` for config/models, `httpx` for HTTP, and the `openai`
SDK for the optional LLM layers. Tooling: `uv` + `hatchling` for packaging,
`pytest` for tests, `ruff` for lint/format, `mypy` for type-checking, and
GitHub Actions for CI across Python 3.10–3.13. The dependency tree is kept
deliberately small and conservative.

## How can I contribute or report a bug?

Bug reports and feature requests go in the
[issue tracker](https://github.com/LeoMartinezTAMUK/mcp-strike/issues). To
add an attack or an LLM backend, see [CONTRIBUTING.md](CONTRIBUTING.md). To
report a security issue in MCP-Strike itself, see [SECURITY.md](SECURITY.md).

## What's on the roadmap?

HTTP/SSE transport, scan-diffing against a baseline for CI regression
tracking, and user-defined attack patterns. See [ROADMAP.md](ROADMAP.md) for
the full list and what's explicitly out of scope.

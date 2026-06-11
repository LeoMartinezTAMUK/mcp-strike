# Changelog

All notable changes to MCP-Strike are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-06-11

### Added
- `--verbose` / `-v` flag on `scan` and `demo` to surface mcp-strike's own
  debug logging (LLM-response parse failures, etc.) on stderr.

### Fixed
- Scanning a target that can't be launched (mistyped `--command`) or that
  starts but doesn't speak MCP now prints a single clear error line and exits
  with a non-zero code, instead of dumping a deep asyncio/anyio traceback.
- JSON report metadata now reports `null` (not `0`) for the judge's
  `llm_calls_used` / `llm_calls_cap` when the judge was requested but could
  not actually run (for example, `--judge` with no `OPENAI_API_KEY`). This
  matches the documented "null = feature didn't run" semantics and the
  agent's existing behavior.
- `--output-file` to a path that can't be written (e.g. a missing parent
  directory) now reports a clean error instead of a traceback.

### Changed
- The adaptive agent now aborts the rest of its run after a short run of
  consecutive LLM-API failures, rather than retrying against every remaining
  tool. This bounds wall-clock time during an API outage.
- The demo server now prints a "deliberately vulnerable" warning to stderr
  when launched directly in a terminal (suppressed when the scanner spawns
  it over a pipe).
- Packaging now declares its license with a PEP 639 SPDX expression
  (`license = "MIT"`) instead of the legacy file-table form.

### Documentation
- Corrected the demo sample output in the README: the `get_weather` finding
  reports 2 injection markers, not 3.
- Noted that the demo's path-traversal result differs on Windows (no
  `/etc/passwd` to read).
- Updated the test count and coverage figure (97 tests, ~96%); the demo
  server is now excluded from coverage measurement since it runs as a
  subprocess.

### Internal
- Added a `py.typed` marker so downstream type checkers honor the package's
  inline type annotations (PEP 561).
- Added unit tests for the attacks' error / UNCERTAIN branches, the
  benign-argument generator, and the agent's API-outage circuit breaker.
- Added a tag-triggered PyPI release workflow using Trusted Publishing.

## [0.1.0] - 2026-06-05

Initial public release. See [`ROADMAP.md`](ROADMAP.md) for the full feature
list and what's planned next.

### Added
- Active, runtime adversarial scanning of MCP servers over the stdio transport.
- Five static attacks across the three MCP pipeline stages: description
  prompt-injection and overreaching-parameter scans (metadata), a
  path-traversal probe (parameters), and response-injection and
  data-exfiltration probes (response).
- Optional LLM-as-judge layer (OpenAI, `gpt-4o-mini` by default) with a
  per-run call cap.
- Optional adaptive LLM agent that probes each tool over multiple rounds,
  with its own per-run call cap.
- Colorized terminal report and a stable JSON report for CI use.
- A bundled, deliberately-vulnerable demo server with six planted
  vulnerabilities for one-command validation (`mcp-strike demo`).
- Per-MCP-call and per-LLM-call timeouts, and `.env` auto-loading.

[Unreleased]: https://github.com/LeoMartinezTAMUK/mcp-strike/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/LeoMartinezTAMUK/mcp-strike/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/LeoMartinezTAMUK/mcp-strike/releases/tag/v0.1.0

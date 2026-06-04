# Security Policy

MCP-Strike is a security testing tool, so taking its own security seriously is the bar. Thanks for helping keep it solid.

## Reporting a vulnerability in MCP-Strike

If you find a security issue in MCP-Strike itself (not in the deliberately-vulnerable demo server, which is full of planted vulnerabilities on purpose), please report it privately rather than opening a public GitHub issue.

**Preferred channel: GitHub Private Vulnerability Reporting.**

1. Go to the repository's [Security tab](https://github.com/LeoMartinezTAMUK/mcp-strike/security).
2. Click **"Report a vulnerability"**.
3. Fill in the form. GitHub forwards the report to the maintainer privately.

This is the simplest path for both sides: no email setup, no PGP keys, automatic disclosure scheduling, and a clean audit trail.

**Fallback: direct contact.** If you can't use GitHub Private Vulnerability Reporting (for example, because you don't have a GitHub account), contact the maintainer through their [GitHub profile](https://github.com/LeoMartinezTAMUK) and request a private channel.

## What's in scope

In scope:

- The `mcp-strike` CLI, library code, and packaging (`src/mcp_strike/`).
- Anything in the CI workflows under `.github/workflows/` that could leak secrets or enable supply-chain attacks against contributors.
- The bundled `.env` loader and `OPENAI_API_KEY` handling.

Out of scope:

- The deliberately-vulnerable demo server in `src/mcp_strike/demo_server/`. Every "vulnerability" there is planted on purpose for testing; it is not deployed anywhere and shouldn't be.
- Findings against third-party MCP servers you tested with MCP-Strike. Those belong to whoever runs that server. See "Reporting findings against other people's servers" below.
- Issues in upstream dependencies (the `mcp`, `openai`, `typer`, `rich`, `pydantic`, etc. SDKs). Report those to the corresponding project.

## What to expect

- **Acknowledgement** within 7 days of your report being received.
- **Initial assessment** within 14 days, including whether we agree it's a security issue and a target timeline.
- **Coordinated disclosure.** If you'd like to be credited in the fix release notes, say so. If you'd like to publish your own writeup, we'll agree on a coordinated date.

MCP-Strike is a solo, part-time project. Timelines reflect that. We'll be honest about what we can ship and when.

## Reporting findings against other people's servers

MCP-Strike is designed for testing servers you own. If you use it against a server you're authorized to test and find a real vulnerability:

- Contact the operator of that server directly and privately, not us.
- Follow standard coordinated-disclosure norms: give them a reasonable window to fix the issue before publishing.
- Do not attach scan output containing sensitive details (real credentials, real PII, exfiltrated content) to a public issue.

We do not act as an intermediary for third-party vulnerability reports.

## Hall of fame

Once we receive our first reported and fixed vulnerability, this section will list reporters who agreed to be credited.

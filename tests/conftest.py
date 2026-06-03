"""Pytest conftest for MCP-Strike tests.

Pytest auto-discovers this file and runs it before any test module is
imported. We use it to load the project's ``.env`` so integration tests
gated on ``OPENAI_API_KEY`` (and similar) pick up values placed in ``.env``
the same way the CLI does.

Without this, pytest would only see env vars exported into the shell; tests
gated on ``OPENAI_API_KEY`` would silently skip even when the key is
configured in ``.env``. Production code already handles the .env path via
``mcp_strike.cli._run_scan``; this hook gives tests the same convenience.

In CI (where ``.env`` doesn't exist), :func:`load_dotenv` is a no-op, so
this file is safe to ship.
"""

from __future__ import annotations

from pathlib import Path

from mcp_strike.config.dotenv import load_dotenv

# This conftest lives in ``tests/``; the project root is one level up.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

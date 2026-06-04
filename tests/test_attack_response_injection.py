"""Test the Stage-3 response-injection probe against the demo server."""

from __future__ import annotations

import asyncio
import sys

from mcp_strike.attacks.base import AttackResult, Verdict
from mcp_strike.attacks.response_injection import ResponseInjectionProbe
from mcp_strike.target import open_stdio_target


async def _run_against_demo_async() -> list[AttackResult]:
    async with open_stdio_target(
        command=sys.executable,
        args=["-m", "mcp_strike.demo_server"],
    ) as target:
        return await ResponseInjectionProbe().execute(target)


def _run_against_demo() -> list[AttackResult]:
    return asyncio.run(_run_against_demo_async())


def test_response_injection_against_demo() -> None:
    """Fires on `get_news` (planted VULN #4); silent on clean tools."""
    results = _run_against_demo()
    by_tool = {r.target_tool: r for r in results}

    # Planted vuln fires: get_news returns the injection payload.
    assert by_tool["get_news"].verdict == Verdict.SUCCESS
    matched = by_tool["get_news"].evidence["matched_markers"]
    assert any("ignore" in m for m in matched)

    # Benign-response tools shouldn't false-positive.
    # (get_weather and submit_feedback return clean text; fetch_status
    # returns exfil text but no injection markers.)
    assert by_tool["get_weather"].verdict == Verdict.FAILURE
    assert by_tool["submit_feedback"].verdict == Verdict.FAILURE
    assert by_tool["fetch_status"].verdict == Verdict.FAILURE


def test_uncertain_when_tool_returns_in_band_error() -> None:
    """`read_file('status')` returns isError=True (no such file).

    MCP wraps the FileNotFoundError as an in-band CallToolResult with
    ``isError=True``, not a transport exception. The probe should notice
    that and emit UNCERTAIN; it never observed the tool's normal
    behavior, so claiming FAILURE would be a false negative.
    """
    results = _run_against_demo()
    by_tool = {r.target_tool: r for r in results}

    assert by_tool["read_file"].verdict == Verdict.UNCERTAIN
    # Rationale should reference the error-response branch we took.
    assert "error" in by_tool["read_file"].rationale.lower()

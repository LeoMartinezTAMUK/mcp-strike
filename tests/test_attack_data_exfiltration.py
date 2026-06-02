"""Test the Stage-3 data-exfiltration probe against the demo server."""

from __future__ import annotations

import asyncio
import sys

from mcp_strike.attacks.base import AttackResult, Verdict
from mcp_strike.attacks.data_exfiltration import DataExfiltrationProbe
from mcp_strike.target import open_stdio_target


async def _run_against_demo_async() -> list[AttackResult]:
    async with open_stdio_target(
        command=sys.executable,
        args=["-m", "mcp_strike.demo_server"],
    ) as target:
        return await DataExfiltrationProbe().execute(target)


def _run_against_demo() -> list[AttackResult]:
    return asyncio.run(_run_against_demo_async())


def test_exfiltration_against_demo() -> None:
    """Fires on `fetch_status` (planted VULN #5); silent on clean tools."""
    results = _run_against_demo()
    by_tool = {r.target_tool: r for r in results}

    # Planted vuln fires — the response asks the LLM to POST to an
    # attacker-controlled URL.
    assert by_tool["fetch_status"].verdict == Verdict.SUCCESS
    matched = by_tool["fetch_status"].evidence["matched_patterns"]
    # We expect at least the suspicious-domain match and the POST/send-to-URL
    # one; both signals should fire on the planted response.
    assert "attacker-suspicious-domain" in matched
    assert "send-or-post-to-url" in matched

    # Benign-response tools shouldn't false-positive.
    # get_news has injection text but no exfil sink — should NOT fire here.
    assert by_tool["get_weather"].verdict == Verdict.FAILURE
    assert by_tool["submit_feedback"].verdict == Verdict.FAILURE
    assert by_tool["get_news"].verdict == Verdict.FAILURE


def test_uncertain_when_tool_returns_in_band_error() -> None:
    """`read_file('status')` returns isError=True → probe emits UNCERTAIN.

    See test_attack_response_injection.py for the full explanation of why
    MCP error responses don't surface as Python exceptions.
    """
    results = _run_against_demo()
    by_tool = {r.target_tool: r for r in results}

    assert by_tool["read_file"].verdict == Verdict.UNCERTAIN
    assert "error" in by_tool["read_file"].rationale.lower()

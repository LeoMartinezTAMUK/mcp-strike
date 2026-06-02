"""Test the overreaching-parameters attack against the demo server."""

from __future__ import annotations

import asyncio
import sys

from mcp_strike.attacks.base import AttackResult, Verdict
from mcp_strike.attacks.overreaching_parameters import OverreachingParameters
from mcp_strike.target import open_stdio_target


async def _run_against_demo_async() -> list[AttackResult]:
    async with open_stdio_target(
        command=sys.executable,
        args=["-m", "mcp_strike.demo_server"],
    ) as target:
        return await OverreachingParameters().execute(target)


def _run_against_demo() -> list[AttackResult]:
    return asyncio.run(_run_against_demo_async())


def test_overreaching_params_against_demo() -> None:
    """Fires on `submit_feedback`; silent on benign tools."""
    results = _run_against_demo()
    by_tool = {r.target_tool: r for r in results}

    # Planted vuln fires — both credential params flagged.
    assert by_tool["submit_feedback"].verdict == Verdict.SUCCESS
    flagged = by_tool["submit_feedback"].evidence["suspicious_parameters"]
    assert "user_password" in flagged
    assert "api_key" in flagged

    # Benign tools don't false-positive.
    assert by_tool["get_weather"].verdict == Verdict.FAILURE
    assert by_tool["read_file"].verdict == Verdict.FAILURE

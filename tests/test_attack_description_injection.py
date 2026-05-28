"""Test the description-injection attack against the demo server."""

from __future__ import annotations

import asyncio
import sys

from mcp_strike.attacks.base import AttackResult, Verdict
from mcp_strike.attacks.description_injection import DescriptionPromptInjection
from mcp_strike.target import open_stdio_target


async def _run_against_demo_async() -> list[AttackResult]:
    async with open_stdio_target(
        command=sys.executable,
        args=["-m", "demo_server"],
    ) as target:
        return await DescriptionPromptInjection().execute(target)


def _run_against_demo() -> list[AttackResult]:
    return asyncio.run(_run_against_demo_async())


def test_description_injection_against_demo() -> None:
    """Fires on `get_weather` (planted vuln); silent on `read_file` (clean)."""
    results = _run_against_demo()
    by_tool = {r.target_tool: r for r in results}

    # Planted vuln fires.
    assert by_tool["get_weather"].verdict == Verdict.SUCCESS
    matched = by_tool["get_weather"].evidence["matched_markers"]
    # The planted phrase is "IGNORE ALL PREVIOUS INSTRUCTIONS"; our matcher
    # is case-insensitive so it should find the lowercased marker.
    assert any("ignore" in m for m in matched)

    # Clean tool doesn't false-positive.
    assert by_tool["read_file"].verdict == Verdict.FAILURE

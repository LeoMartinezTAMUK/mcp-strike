"""Smoke test for the end-to-end discovery path.

Launch the deliberately-vulnerable demo MCP server as a subprocess, connect to
it via the Target adapter, and verify the planted tool surface is discovered
with the planted-vuln description intact.

We deliberately don't depend on `pytest-asyncio`; wrapping the async call in
`asyncio.run` inside a sync test keeps the test simple and removes one dev dep.
"""

from __future__ import annotations

import asyncio
import sys

from mcp_strike.target import ToolInfo, open_stdio_target


async def _discover_demo_tools_async() -> list[ToolInfo]:
    # `sys.executable` is the absolute path to the Python interpreter pytest
    # itself is running under; no PATH guessing, no virtualenv surprises.
    async with open_stdio_target(
        command=sys.executable,
        args=["-m", "mcp_strike.demo_server"],
    ) as target:
        return await target.list_tools()


def _discover_demo_tools() -> list[ToolInfo]:
    return asyncio.run(_discover_demo_tools_async())


def test_demo_server_exposes_planted_vuln_tools() -> None:
    """The original planted-vuln tools must be discoverable.

    The demo server has grown additional planted tools over time (e.g.
    `submit_feedback` for the overreaching-parameters attack), so we
    check for presence, not exact equality.
    """
    tools = _discover_demo_tools()
    tool_names = {tool.name for tool in tools}

    assert "get_weather" in tool_names, f"missing get_weather; got {tool_names}"
    assert "read_file" in tool_names, f"missing read_file; got {tool_names}"


def test_prompt_injection_string_lands_in_description() -> None:
    """The Stage-1 planted vuln must round-trip through the protocol.

    If the MCP SDK ever changes how it surfaces descriptions, this test will
    catch it, and it doubles as documentation that the demo tool really is
    carrying the malicious string the description-injection attack scans for.
    """
    tools = _discover_demo_tools()
    by_name = {tool.name: tool for tool in tools}

    weather_desc = by_name["get_weather"].description
    # Match on a distinctive marker rather than the exact phrase, so minor
    # wording tweaks in demo_server don't break the test.
    assert "IGNORE ALL PREVIOUS INSTRUCTIONS" in weather_desc

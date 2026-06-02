"""Test the path-traversal probe against the demo server.

Linux-only: the probe targets ``/etc/passwd`` and looks for the
``root:x:0:0:`` signature, which exists on Linux but not macOS or Windows
in the same form. The probe code itself is cross-platform — only this
test's assertion is Linux-gated.
"""

from __future__ import annotations

import asyncio
import sys

import pytest

from mcp_strike.attacks.base import AttackResult, Verdict
from mcp_strike.attacks.path_traversal import PathTraversalProbe
from mcp_strike.target import open_stdio_target


async def _run_against_demo_async() -> list[AttackResult]:
    async with open_stdio_target(
        command=sys.executable,
        args=["-m", "mcp_strike.demo_server"],
    ) as target:
        return await PathTraversalProbe().execute(target)


def _run_against_demo() -> list[AttackResult]:
    return asyncio.run(_run_against_demo_async())


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="Probe targets /etc/passwd, which has Linux-specific contents",
)
def test_path_traversal_fires_on_read_file() -> None:
    """`read_file` is unsanitized — traversal should succeed.

    Other tools (``get_weather``, ``submit_feedback``) take string params
    too but don't expose the filesystem, so the probe lands on FAILURE
    against them — that asymmetry is exactly what makes the attack useful.
    """
    results = _run_against_demo()
    by_tool = {r.target_tool: r for r in results}

    # Planted vuln fires.
    assert by_tool["read_file"].verdict == Verdict.SUCCESS
    assert by_tool["read_file"].evidence["parameter"] == "path"
    assert by_tool["read_file"].evidence["signature"] == "root:x:0:0:"

    # Other string-parameter tools don't expose the filesystem; should NOT
    # land on SUCCESS. (FAILURE or UNCERTAIN both acceptable here — the
    # important property is "no false positive".)
    assert by_tool["get_weather"].verdict != Verdict.SUCCESS
    assert by_tool["submit_feedback"].verdict != Verdict.SUCCESS

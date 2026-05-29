"""Proof that VULN #6 (check_session) is invisible to every static attack.

This test exists to lock in the *premise* of the Phase-3 adaptive agent:
that there are vulnerability classes static pattern matching can't catch.
If a future commit accidentally makes one of the static attacks flag
``check_session`` as SUCCESS, this test fails and we re-evaluate.

(The agent's ability to actually catch VULN #6 is exercised by the
real-API integration test in ``test_agent_adaptive.py``.)
"""

from __future__ import annotations

import asyncio
import sys

from mcp_strike.attacks.base import Verdict
from mcp_strike.attacks.data_exfiltration import DataExfiltrationProbe
from mcp_strike.attacks.description_injection import DescriptionPromptInjection
from mcp_strike.attacks.overreaching_parameters import OverreachingParameters
from mcp_strike.attacks.path_traversal import PathTraversalProbe
from mcp_strike.attacks.response_injection import ResponseInjectionProbe
from mcp_strike.target import open_stdio_target


async def _run_all_static_attacks_async() -> dict[str, list]:
    """Run every static attack against the demo, return results keyed by attack name."""
    async with open_stdio_target(
        command=sys.executable,
        args=["-m", "demo_server"],
    ) as target:
        return {
            "description_prompt_injection": await DescriptionPromptInjection().execute(target),
            "overreaching_parameters": await OverreachingParameters().execute(target),
            "path_traversal_probe": await PathTraversalProbe().execute(target),
            "response_injection_probe": await ResponseInjectionProbe().execute(target),
            "data_exfiltration_probe": await DataExfiltrationProbe().execute(target),
        }


def test_no_static_attack_flags_check_session_as_success() -> None:
    """check_session must NOT land on SUCCESS for any static attack.

    Acceptable outcomes per static attack: FAILURE (probed, no signal),
    UNCERTAIN (couldn't probe), or absent from results entirely (out of
    scope — e.g. path traversal needs a string parameter and check_session
    has none). Anything is fine except SUCCESS.
    """
    results_by_attack = asyncio.run(_run_all_static_attacks_async())

    for attack_name, results in results_by_attack.items():
        for r in results:
            if r.target_tool == "check_session":
                assert r.verdict != Verdict.SUCCESS, (
                    f"{attack_name} unexpectedly flagged check_session as SUCCESS. "
                    f"VULN #6 was designed to be invisible to static patterns; "
                    f"either the planted vuln has changed shape or the attack "
                    f"heuristic has gotten broader. Re-evaluate."
                )

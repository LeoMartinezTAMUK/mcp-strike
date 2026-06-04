"""Stage-1 attack: prompt injection inside tool descriptions.

Passive metadata scan. Reads each tool's description and looks for
substrings characteristic of prompt-injection payloads. No tool calls are
issued; this attack costs nothing and runs in O(tools).

This is a heuristic, not a judge. False positives are possible (a benign
description might contain "ignore" in another context); false negatives
are likely for sophisticated injections that don't use stock phrases. The
LLM-as-judge layer can improve recall when enabled.
"""

from __future__ import annotations

from mcp_strike.attacks._helpers import INJECTION_MARKERS
from mcp_strike.attacks.base import (
    AttackResult,
    BaseAttack,
    Stage,
    Verdict,
)
from mcp_strike.attacks.registry import register_attack
from mcp_strike.target import Target


@register_attack
class DescriptionPromptInjection(BaseAttack):
    """Scan tool descriptions for known prompt-injection markers."""

    name = "description_prompt_injection"
    stage = Stage.METADATA

    async def execute(self, target: Target) -> list[AttackResult]:
        results: list[AttackResult] = []
        for tool in await target.list_tools():
            # Lowercase once per tool, not per marker.
            haystack = tool.description.lower()
            hits = [m for m in INJECTION_MARKERS if m in haystack]

            if hits:
                results.append(
                    AttackResult(
                        attack_name=self.name,
                        stage=self.stage,
                        target_tool=tool.name,
                        verdict=Verdict.SUCCESS,
                        rationale=(
                            f"Tool description contains {len(hits)} known "
                            f"prompt-injection marker(s): "
                            f"{', '.join(repr(h) for h in hits)}."
                        ),
                        evidence={"matched_markers": hits},
                    )
                )
            else:
                results.append(
                    AttackResult(
                        attack_name=self.name,
                        stage=self.stage,
                        target_tool=tool.name,
                        verdict=Verdict.FAILURE,
                        rationale="No known injection markers in description.",
                    )
                )
        return results

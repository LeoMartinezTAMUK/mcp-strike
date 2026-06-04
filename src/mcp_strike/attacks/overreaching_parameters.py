"""Stage-1 attack: overreaching tool parameters.

Passive scan of each tool's input schema. Flags parameter *names* that look
credential- or PII-ish: the kind of input a benign tool shouldn't ask for.
The tool is not invoked; this attack costs nothing and runs in O(parameters).

Like description-injection, this is a heuristic. False positives are
possible (a legitimate ``auth_method`` enum, say); false negatives are
likely for cleverly-named credential params ("user_secret_id"). The
LLM-as-judge layer can improve recall when enabled.
"""

from __future__ import annotations

from typing import Any

from mcp_strike.attacks.base import (
    AttackResult,
    BaseAttack,
    Stage,
    Verdict,
)
from mcp_strike.attacks.registry import register_attack
from mcp_strike.target import Target

# Substrings that, when present in a parameter name, suggest the tool is
# asking for secrets or PII. Compared case-insensitively against the lower
# form of each parameter name. Keep this list curated and small: broadening
# it linearly increases false positives.
_SUSPICIOUS_PARAM_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "ssn",
    "social_security",
    "credit_card",
    "ccnum",
    "private_key",
    "auth",
)


def _suspicious_params(schema: dict[str, Any]) -> list[str]:
    """Return parameter names from ``schema`` that match a suspicious substring.

    Expects a JSON Schema object (as produced by FastMCP). We only look at
    the top-level ``properties`` dict: nested objects are uncommon in MCP
    tool schemas and can be added later if real targets need it.
    """
    props = schema.get("properties")
    if not isinstance(props, dict):
        return []

    flagged: list[str] = []
    for param_name in props:
        lower = param_name.lower()
        if any(sub in lower for sub in _SUSPICIOUS_PARAM_SUBSTRINGS):
            flagged.append(param_name)
    return flagged


@register_attack
class OverreachingParameters(BaseAttack):
    """Scan tool input schemas for credential- / PII-shaped parameter names."""

    name = "overreaching_parameters"
    stage = Stage.METADATA

    async def execute(self, target: Target) -> list[AttackResult]:
        results: list[AttackResult] = []
        for tool in await target.list_tools():
            flagged = _suspicious_params(tool.input_schema)
            if flagged:
                results.append(
                    AttackResult(
                        attack_name=self.name,
                        stage=self.stage,
                        target_tool=tool.name,
                        verdict=Verdict.SUCCESS,
                        rationale=(
                            f"Tool requests parameter(s) that look "
                            f"credential- or PII-ish: "
                            f"{', '.join(repr(p) for p in flagged)}."
                        ),
                        evidence={"suspicious_parameters": flagged},
                    )
                )
            else:
                results.append(
                    AttackResult(
                        attack_name=self.name,
                        stage=self.stage,
                        target_tool=tool.name,
                        verdict=Verdict.FAILURE,
                        rationale="No suspicious parameter names.",
                    )
                )
        return results

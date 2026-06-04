"""Stage-3 attack: data-exfiltration patterns in tool responses.

Active attack. Invokes each tool with benign input and scans the response
for sinks the response is trying to coax the calling LLM into: POST-to-URL
instructions, "send credentials to X" phrasings, suspicious domains.

Distinct from response-injection: injection wants the *LLM* to do something
arbitrary; exfiltration wants it to *send data out*. The patterns overlap
sometimes but the verdicts should be reported independently.

Verdict mapping: a pattern hit yields ``SUCCESS``, no hit yields
``FAILURE``, a rejected call yields ``UNCERTAIN``. The judge layer
resolves UNCERTAIN.
"""

from __future__ import annotations

import re

from mcp_strike.attacks._helpers import (
    EVIDENCE_EXCERPT_CHARS,
    EVIDENCE_SHORT_EXCERPT_CHARS,
    benign_args,
    is_error_result,
    response_text,
)
from mcp_strike.attacks.base import (
    AttackResult,
    BaseAttack,
    Stage,
    Verdict,
)
from mcp_strike.attacks.registry import register_attack
from mcp_strike.target import Target, ToolInfo

# Exfiltration patterns. Each is (label, regex). Compiled once at module
# load. Curated for high precision: false positives are worse than false
# negatives here because the judge will resolve the latter.
#
# Patterns:
#   - "send-or-post-to-url": a verb that pushes data ("post"/"send") near a URL.
#     A 0..80 char gap covers prose like "POST your API key and full history to URL".
#   - "send-credentials": a verb pushing credentials (password / api key / token).
#   - "attacker-suspicious-domain": URL whose host contains
#     attacker-flavoured words.
_EXFIL_PATTERNS: tuple[tuple[str, str], ...] = (
    ("send-or-post-to-url", r"(?:post|send)\s+.{0,80}https?://"),
    (
        "send-credentials",
        r"(?:post|send)\s+.{0,40}(credentials|password|api[\s_-]?key|token)",
    ),
    (
        "attacker-suspicious-domain",
        r"https?://[a-z0-9.-]*(evil|attacker|exfil|drop)[a-z0-9.-]*",
    ),
)

_COMPILED_EXFIL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (label, re.compile(pattern, re.IGNORECASE | re.DOTALL))
    for label, pattern in _EXFIL_PATTERNS
]


@register_attack
class DataExfiltrationProbe(BaseAttack):
    """Probe each tool's RESPONSE for exfiltration-style content."""

    name = "data_exfiltration_probe"
    stage = Stage.RESPONSE

    async def execute(self, target: Target) -> list[AttackResult]:
        results: list[AttackResult] = []
        for tool in await target.list_tools():
            result = await self._probe_one(tool, target)
            if result is not None:
                results.append(result)
        return results

    async def _probe_one(
        self, tool: ToolInfo, target: Target
    ) -> AttackResult | None:
        args = benign_args(tool.input_schema)
        if args is None:
            return None

        try:
            call_result = await target.call_tool(tool.name, args)
        except Exception as exc:
            # Transport or protocol error (rare). Treat as UNCERTAIN.
            return AttackResult(
                attack_name=self.name,
                stage=self.stage,
                target_tool=tool.name,
                verdict=Verdict.UNCERTAIN,
                rationale=f"Call raised at transport layer: {exc}",
                evidence={"args_tried": args},
            )

        text = response_text(call_result)

        # See response_injection.py for the full rationale: MCP wraps tool
        # exceptions as in-band errors, so we have to check `isError`
        # explicitly. Error responses are treated as UNCERTAIN.
        if is_error_result(call_result):
            return AttackResult(
                attack_name=self.name,
                stage=self.stage,
                target_tool=tool.name,
                verdict=Verdict.UNCERTAIN,
                rationale=(
                    "Tool returned an error response to benign input; "
                    "cannot probe normal behavior."
                ),
                evidence={
                    "args_tried": args,
                    "error_excerpt": text[:EVIDENCE_SHORT_EXCERPT_CHARS],
                },
            )

        hits = [
            label for label, regex in _COMPILED_EXFIL_PATTERNS if regex.search(text)
        ]

        if hits:
            return AttackResult(
                attack_name=self.name,
                stage=self.stage,
                target_tool=tool.name,
                verdict=Verdict.SUCCESS,
                rationale=(
                    f"Tool response matched {len(hits)} exfiltration "
                    f"pattern(s): {', '.join(hits)}."
                ),
                evidence={
                    "matched_patterns": hits,
                    "args_used": args,
                    "response_excerpt": text[:EVIDENCE_EXCERPT_CHARS],
                },
            )

        return AttackResult(
            attack_name=self.name,
            stage=self.stage,
            target_tool=tool.name,
            verdict=Verdict.FAILURE,
            rationale="No exfiltration patterns matched.",
            evidence={
                "args_used": args,
                "response_excerpt": text[:EVIDENCE_SHORT_EXCERPT_CHARS],
            },
        )

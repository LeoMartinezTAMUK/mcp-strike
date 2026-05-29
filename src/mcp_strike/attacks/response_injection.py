"""Stage-3 attack: prompt injection inside tool RESPONSES.

Active attack — the flagship dynamic check from PLAN.md §7. Invokes each
tool with benign input and scans the response text for substrings
characteristic of prompt-injection payloads aimed at the *calling* LLM.
This is the canonical "indirect" or "response-channel" injection.

Tools that can't be called with benign input (require types we don't model,
or that raise on our placeholder input) get an ``UNCERTAIN`` result so the
LLM judge can investigate when enabled.

Phase 2 ships the heuristic only — markers in the response → ``SUCCESS``,
none → ``FAILURE``, call rejected → ``UNCERTAIN``. The judge resolves the
UNCERTAIN cases.
"""

from __future__ import annotations

from mcp_strike.attacks._helpers import benign_args, is_error_result, response_text
from mcp_strike.attacks.base import (
    AttackResult,
    BaseAttack,
    Stage,
    Verdict,
)
from mcp_strike.attacks.registry import register_attack
from mcp_strike.target import Target, ToolInfo

# Same canonical markers as `description_prompt_injection`. The patterns
# are pipeline-stage-agnostic — an injection in metadata and an injection
# in response text look the same.
_INJECTION_MARKERS: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore the above",
    "disregard previous",
    "you are now",
    "you must",
    "as an ai",
    "system:",
    "<|im_start|>",
    "</system>",
    "do not mention",
    "do not tell the user",
)


@register_attack
class ResponseInjectionProbe(BaseAttack):
    """Probe each tool's RESPONSE for prompt-injection content."""

    name = "response_injection_probe"
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
        """Probe a single tool. Returns ``None`` if we can't build benign args."""
        args = benign_args(tool.input_schema)
        if args is None:
            # Out of scope — schema is too exotic for this attack.
            return None

        try:
            call_result = await target.call_tool(tool.name, args)
        except Exception as exc:
            # Transport / protocol error (rare). Treat as UNCERTAIN.
            return AttackResult(
                attack_name=self.name,
                stage=self.stage,
                target_tool=tool.name,
                verdict=Verdict.UNCERTAIN,
                rationale=f"Call raised at transport layer: {exc}",
                evidence={"args_tried": args},
            )

        text = response_text(call_result)

        # MCP wraps tool exceptions as in-band errors (CallToolResult with
        # isError=True), so ``try/except`` above doesn't catch them. We
        # explicitly check the flag and treat error responses as UNCERTAIN:
        # we never observed the tool's normal behavior, so we can't claim
        # FAILURE with confidence — the judge can decide if enabled.
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
                evidence={"args_tried": args, "error_excerpt": text[:200]},
            )

        hits = [m for m in _INJECTION_MARKERS if m in text.lower()]

        if hits:
            return AttackResult(
                attack_name=self.name,
                stage=self.stage,
                target_tool=tool.name,
                verdict=Verdict.SUCCESS,
                rationale=(
                    f"Tool response contains {len(hits)} known "
                    f"prompt-injection marker(s): "
                    f"{', '.join(repr(h) for h in hits)}."
                ),
                evidence={
                    "matched_markers": hits,
                    "args_used": args,
                    # Cap excerpt length so reports stay readable.
                    "response_excerpt": text[:500],
                },
            )

        return AttackResult(
            attack_name=self.name,
            stage=self.stage,
            target_tool=tool.name,
            verdict=Verdict.FAILURE,
            rationale="No injection markers in response.",
            evidence={"args_used": args, "response_excerpt": text[:200]},
        )

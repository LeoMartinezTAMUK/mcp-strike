"""Adaptive LLM-driven attacker.

For each tool exposed by the target, an LLM loops:

  1. See the tool surface + the accumulated probe history.
  2. Either propose a payload to send next, OR declare a final verdict.
  3. We execute the proposed call and feed the response back in.

Loop is bounded by ``max_rounds`` per tool. Each round = one LLM call (a
proposal). If the LLM hasn't declared a verdict by the time we exhaust the
rounds, we make one more LLM call asking for a final verdict from history.
So per tool we make at most ``max_rounds + 1`` real LLM calls.

A separate per-run cap (``max_calls``, default 50) bounds total spend
across the whole scan, independently of the judge's cap.

Failure-mode contract: this class never raises out of public methods. API
errors, malformed responses, and tool-call failures all flow into
``AttackResult`` rows so the scan continues.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Protocol

from mcp_strike.attacks import AttackResult, Stage, Verdict
from mcp_strike.attacks._helpers import is_error_result, response_text
from mcp_strike.target import Target, ToolInfo

# Defaults (also documented in CLI help text + README).
_DEFAULT_MODEL = "gpt-4o-mini"
_DEFAULT_MAX_ROUNDS = 3
_DEFAULT_MAX_CALLS = 50

# The attack_name carried by every AttackResult the agent emits. Single
# constant so the CLI's --only filter can target it.
ATTACK_NAME = "adaptive_agent"

# Caps for evidence payloads so reports stay readable.
_RESPONSE_EXCERPT_CHARS = 500
_RATIONALE_MAX_CHARS = 500


class _AsyncOpenAILike(Protocol):
    """Structural type for the bits of ``openai.AsyncOpenAI`` we use."""

    @property
    def chat(self) -> Any: ...


@dataclass
class _ProbeOutcome:
    """One round's input + observed output. Accumulated as agent history."""

    arguments: dict[str, Any]
    hypothesis: str
    response_excerpt: str
    is_error: bool


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are an adaptive security testing agent for MCP-Strike. Given a "
    "tool exposed by an MCP server, you will probe it to find security "
    "vulnerabilities aimed at LLM-based callers of that tool.\n\n"
    "Vulnerability classes to consider include:\n"
    "- Tool description contains prompt-injection content.\n"
    "- Parameters ask for credentials, secrets, or PII.\n"
    "- Tool input is handled unsafely (path traversal, command injection).\n"
    "- Tool response contains prompt injection aimed at the calling LLM.\n"
    "- Tool response contains data-exfiltration sinks (URLs, 'send to ...').\n"
    "- Tool response uses social engineering (asking user for secrets).\n"
    "- Anything else that could harm a user whose LLM trusts this tool.\n\n"
    "In each round, choose ONE of two actions:\n"
    "  A) PROBE: respond with JSON containing 'arguments' (the args to call "
    "the tool with) and 'hypothesis' (what vuln class this probe tests).\n"
    "  B) VERDICT: respond with JSON containing 'verdict' "
    "('success'|'failure'|'uncertain'), 'rationale' (<=300 chars), and "
    "'stage' ('metadata'|'parameters'|'response').\n"
    "Use exactly one form per response — never both. Respond ONLY with the "
    "JSON."
)


def _build_propose_prompt(tool: ToolInfo, history: list[_ProbeOutcome]) -> str:
    """User-message body for a proposal/verdict round."""
    history_block = _render_history(history)
    return (
        f"Tool: {tool.name}\n"
        f"Description: {tool.description}\n"
        f"Input schema: {json.dumps(tool.input_schema)}\n\n"
        f"Probe history so far:\n{history_block}\n\n"
        "If you have enough evidence, return a VERDICT JSON. Otherwise "
        "return a PROBE JSON to try next."
    )


def _build_final_prompt(tool: ToolInfo, history: list[_ProbeOutcome]) -> str:
    """User-message body for the forced final verdict (after rounds exhausted)."""
    history_block = _render_history(history)
    return (
        f"Tool: {tool.name}\n"
        f"Description: {tool.description}\n"
        f"Input schema: {json.dumps(tool.input_schema)}\n\n"
        f"Probe history (final):\n{history_block}\n\n"
        "The round limit is reached. Render your final VERDICT JSON now: "
        "{'verdict': 'success'|'failure'|'uncertain', 'rationale': '...', "
        "'stage': 'metadata'|'parameters'|'response'}."
    )


def _render_history(history: list[_ProbeOutcome]) -> str:
    if not history:
        return "(none yet)"
    parts: list[str] = []
    for i, item in enumerate(history, start=1):
        parts.append(
            f"  Round {i}:\n"
            f"    hypothesis: {item.hypothesis}\n"
            f"    arguments:  {json.dumps(item.arguments)}\n"
            f"    is_error:   {item.is_error}\n"
            f"    response:   {item.response_excerpt}"
        )
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Adaptive agent
# ---------------------------------------------------------------------------


class AdaptiveAgent:
    """Adaptive LLM-driven attacker."""

    def __init__(
        self,
        *,
        client: _AsyncOpenAILike,
        model: str = _DEFAULT_MODEL,
        max_rounds: int = _DEFAULT_MAX_ROUNDS,
        max_calls: int = _DEFAULT_MAX_CALLS,
    ) -> None:
        self._client = client
        self._model = model
        self._max_rounds = max_rounds
        self._max_calls = max_calls
        # Counter of *real* LLM calls made. Reset across instances; for one
        # scan run, reuse a single instance to share the budget.
        self._calls_made = 0

    @property
    def calls_made(self) -> int:
        """How many real LLM calls have been made so far this run."""
        return self._calls_made

    @property
    def max_calls(self) -> int:
        return self._max_calls

    @classmethod
    def from_env(
        cls,
        *,
        model: str | None = None,
        max_rounds: int = _DEFAULT_MAX_ROUNDS,
        max_calls: int = _DEFAULT_MAX_CALLS,
    ) -> AdaptiveAgent:
        """Construct using ``OPENAI_API_KEY`` (raises OSError if unset).

        Model resolution: ``model`` arg > ``$MCP_STRIKE_AGENT_MODEL`` >
        default (gpt-4o-mini).
        """
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise OSError(
                "OPENAI_API_KEY is not set. Set it in your environment "
                "or pass --no-agent to disable the adaptive agent."
            )
        resolved_model = (
            model
            or os.environ.get("MCP_STRIKE_AGENT_MODEL")
            or _DEFAULT_MODEL
        )
        from openai import AsyncOpenAI

        return cls(
            client=AsyncOpenAI(api_key=api_key),
            model=resolved_model,
            max_rounds=max_rounds,
            max_calls=max_calls,
        )

    # ------------------------------------------------------------------ scan

    async def attack_all_tools(
        self, tools: list[ToolInfo], target: Target
    ) -> list[AttackResult]:
        """Run the agent over each tool. Returns one AttackResult per tool.

        Tools encountered after the call cap is reached still get an
        AttackResult (verdict=UNCERTAIN, rationale=cap-reached) so they
        appear in reports.
        """
        results: list[AttackResult] = []
        for tool in tools:
            results.append(await self.attack_one_tool(tool, target))
        return results

    async def attack_one_tool(
        self, tool: ToolInfo, target: Target
    ) -> AttackResult:
        """Probe a single tool and return one AttackResult."""
        if self._calls_made >= self._max_calls:
            return _cap_reached_result(tool, calls_made=self._calls_made, cap=self._max_calls)

        history: list[_ProbeOutcome] = []

        for _ in range(self._max_rounds):
            if self._calls_made >= self._max_calls:
                # Mid-scan cap hit. Best-effort verdict from history.
                return _cap_reached_result(
                    tool, calls_made=self._calls_made, cap=self._max_calls, history=history
                )

            parsed = await self._call_llm(
                _build_propose_prompt(tool, history),
                consume_budget=True,
            )

            # LLM declared early verdict.
            if isinstance(parsed.get("verdict"), str):
                return _result_from_verdict(tool, parsed, history, model=self._model)

            # Otherwise treat as a probe. Validate shape.
            args = parsed.get("arguments")
            hypothesis = str(parsed.get("hypothesis", ""))
            if not isinstance(args, dict):
                # LLM hallucinated a bad shape. Record the round and try again.
                history.append(
                    _ProbeOutcome(
                        arguments={},
                        hypothesis=hypothesis,
                        response_excerpt="(agent proposed non-dict args; round skipped)",
                        is_error=True,
                    )
                )
                continue

            # Execute the probe.
            history.append(await _execute_probe(target, tool.name, args, hypothesis))

        # Round limit reached without an early verdict. One final LLM call.
        if self._calls_made >= self._max_calls:
            return _cap_reached_result(
                tool, calls_made=self._calls_made, cap=self._max_calls, history=history
            )

        parsed = await self._call_llm(
            _build_final_prompt(tool, history),
            consume_budget=True,
        )
        return _result_from_verdict(tool, parsed, history, model=self._model)

    # ----------------------------------------------------------------- LLM I/O

    async def _call_llm(self, user_prompt: str, *, consume_budget: bool) -> dict[str, Any]:
        """One LLM call. Returns the parsed JSON dict (empty dict on failure).

        Updates ``self._calls_made`` only when the call actually went out
        and we got a response, regardless of whether the body parsed —
        we paid for the call, the budget should reflect that.
        """
        try:
            response = await self._client.chat.completions.create(
                model=self._model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.2,
            )
        except Exception:
            # Network / upstream error. Don't count toward budget.
            return {}

        if consume_budget:
            self._calls_made += 1

        try:
            content = response.choices[0].message.content or "{}"
            return json.loads(content)
        except (KeyError, IndexError, AttributeError, json.JSONDecodeError):
            return {}


# ---------------------------------------------------------------------------
# Module-level helpers (kept outside the class so they're easy to unit-test)
# ---------------------------------------------------------------------------


async def _execute_probe(
    target: Target,
    tool_name: str,
    arguments: dict[str, Any],
    hypothesis: str,
) -> _ProbeOutcome:
    """Call the tool with ``arguments`` and turn the result into a ProbeOutcome."""
    try:
        call_result = await target.call_tool(tool_name, arguments)
    except Exception as exc:
        return _ProbeOutcome(
            arguments=arguments,
            hypothesis=hypothesis,
            response_excerpt=f"(transport error: {exc})",
            is_error=True,
        )

    return _ProbeOutcome(
        arguments=arguments,
        hypothesis=hypothesis,
        response_excerpt=response_text(call_result)[:_RESPONSE_EXCERPT_CHARS],
        is_error=is_error_result(call_result),
    )


def _parse_stage(raw: Any) -> Stage:
    """Coerce a raw stage string into a Stage enum. Defaults to RESPONSE."""
    if isinstance(raw, str):
        try:
            return Stage(raw.lower())
        except ValueError:
            pass
    return Stage.RESPONSE


def _result_from_verdict(
    tool: ToolInfo,
    parsed: dict[str, Any],
    history: list[_ProbeOutcome],
    *,
    model: str,
) -> AttackResult:
    """Build the final AttackResult for one tool from the LLM's verdict dict."""
    raw_verdict = str(parsed.get("verdict", "")).lower()
    try:
        verdict = Verdict(raw_verdict)
    except ValueError:
        # LLM didn't give a usable verdict — punt to UNCERTAIN.
        verdict = Verdict.UNCERTAIN

    rationale = str(parsed.get("rationale", "")) or "(no rationale provided)"
    rationale = rationale[:_RATIONALE_MAX_CHARS]
    stage = _parse_stage(parsed.get("stage"))

    return AttackResult(
        attack_name=ATTACK_NAME,
        stage=stage,
        target_tool=tool.name,
        verdict=verdict,
        rationale=rationale,
        evidence={
            "rounds_used": len(history),
            "model": model,
            "history": [
                {
                    "hypothesis": h.hypothesis,
                    "arguments": h.arguments,
                    "is_error": h.is_error,
                    "response_excerpt": h.response_excerpt,
                }
                for h in history
            ],
        },
    )


def _cap_reached_result(
    tool: ToolInfo,
    *,
    calls_made: int,
    cap: int,
    history: list[_ProbeOutcome] | None = None,
) -> AttackResult:
    """Build the AttackResult attached when the per-run call cap is reached."""
    return AttackResult(
        attack_name=ATTACK_NAME,
        stage=Stage.RESPONSE,
        target_tool=tool.name,
        verdict=Verdict.UNCERTAIN,
        rationale=(
            f"Agent call cap ({cap}) reached after {calls_made} call(s); "
            f"could not finish probing this tool."
        ),
        evidence={
            "calls_made": calls_made,
            "cap": cap,
            "rounds_partial": 0 if history is None else len(history),
        },
    )

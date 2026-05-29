"""OpenAI-backed LLM judge.

Uses the official ``openai`` Python SDK and the chat-completions endpoint.
Defaults to ``gpt-4o-mini`` — cheap and plenty capable for yes/no judge
work. Override per-instance via the ``model`` arg, per-run via the
``MCP_STRIKE_JUDGE_MODEL`` env var, or per-call via the CLI ``--judge-model``
flag.

Failure-mode contract (see :class:`BaseJudge`): this implementation never
raises out of :meth:`judge`. API errors, parse errors, and missing keys are
all wrapped in a ``ran=False`` (or ``ran=True`` with UNCERTAIN) annotation
so the scan pipeline can keep going.
"""

from __future__ import annotations

import json
import os
from typing import Any, Protocol

from mcp_strike.attacks import AttackResult, JudgeAnnotation, Verdict
from mcp_strike.judge.base import BaseJudge

# The default judge model — cheap, fast, sufficient for yes/no judging.
# Documented in README + .env.example; override via env or CLI.
_DEFAULT_MODEL = "gpt-4o-mini"

# Cap on rationale length pulled from the model response. Stops a misbehaving
# model from blowing out terminal-report column widths.
_MAX_RATIONALE_CHARS = 500

# Cap on the evidence dict we ship to the model. The judge doesn't need the
# whole dump for yes/no work; this keeps prompt size predictable.
_MAX_EVIDENCE_CHARS = 2000


class _AsyncOpenAILike(Protocol):
    """Structural type for the bits of ``openai.AsyncOpenAI`` we use.

    Defined as a Protocol so tests can inject a fake client without
    importing or installing the real SDK in the test environment.
    """

    @property
    def chat(self) -> Any: ...


class OpenAIJudge(BaseJudge):
    """LLM judge backed by OpenAI's chat-completions API."""

    def __init__(
        self,
        *,
        client: _AsyncOpenAILike,
        model: str = _DEFAULT_MODEL,
    ) -> None:
        self._client = client
        self._model = model

    @classmethod
    def from_env(cls, *, model: str | None = None) -> OpenAIJudge:
        """Construct a judge using credentials and model from environment.

        Resolution precedence for the model:
            1. The ``model`` keyword argument (CLI ``--judge-model`` lands here).
            2. ``$MCP_STRIKE_JUDGE_MODEL`` if set.
            3. The default (currently ``gpt-4o-mini``).

        Raises:
            OSError: if ``OPENAI_API_KEY`` is unset. Callers should catch
                this and fall back to NullJudge so the scan can still run.
                (``OSError`` is the canonical builtin for environment-style
                errors; ``EnvironmentError`` is just a deprecated alias.)
        """
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise OSError(
                "OPENAI_API_KEY is not set. Set it in your environment "
                "or pass --no-judge to disable the LLM judge."
            )

        resolved_model = (
            model
            or os.environ.get("MCP_STRIKE_JUDGE_MODEL")
            or _DEFAULT_MODEL
        )

        # Import the SDK lazily — keeps ``import mcp_strike.judge`` cheap
        # for callers that don't end up using OpenAI.
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=api_key)
        return cls(client=client, model=resolved_model)

    async def judge(self, result: AttackResult) -> JudgeAnnotation:
        try:
            response = await self._client.chat.completions.create(
                model=self._model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": self._build_prompt(result)},
                ],
                # Low temperature: judge work should be near-deterministic.
                temperature=0.0,
            )
        except Exception as exc:
            # API errors, network blips, etc. Don't take down the scan;
            # fall back to the heuristic verdict with a diagnostic note.
            return JudgeAnnotation(
                verdict=result.verdict,
                rationale=f"judge call failed: {exc}",
                model=self._model,
                ran=False,
            )

        return self._parse_response(response, result)

    def _parse_response(
        self, response: Any, result: AttackResult
    ) -> JudgeAnnotation:
        """Extract the JSON body and turn it into a JudgeAnnotation.

        Defensive against malformed responses — the SDK's response shape
        could in principle change or be empty. We catch broadly and fall
        back to UNCERTAIN with a diagnostic.
        """
        try:
            content = response.choices[0].message.content or "{}"
            parsed = json.loads(content)
        except (KeyError, IndexError, AttributeError, json.JSONDecodeError) as exc:
            return JudgeAnnotation(
                verdict=Verdict.UNCERTAIN,
                rationale=f"could not parse judge response: {exc}",
                model=self._model,
                ran=True,
            )

        raw_verdict = str(parsed.get("verdict", "")).lower()
        rationale = str(parsed.get("rationale", "no rationale provided"))

        try:
            verdict = Verdict(raw_verdict)
        except ValueError:
            return JudgeAnnotation(
                verdict=Verdict.UNCERTAIN,
                rationale=(
                    f"judge returned unknown verdict {raw_verdict!r}; "
                    f"original rationale: {rationale[:200]}"
                ),
                model=self._model,
                ran=True,
            )

        return JudgeAnnotation(
            verdict=verdict,
            rationale=rationale[:_MAX_RATIONALE_CHARS],
            model=self._model,
            ran=True,
        )

    def _build_prompt(self, result: AttackResult) -> str:
        """Render the user-message body for a single AttackResult.

        Evidence is JSON-serialized (with ``default=str`` to survive any
        non-trivial types attacks might tuck into the dict) and truncated.
        """
        evidence_json = json.dumps(result.evidence, default=str)
        if len(evidence_json) > _MAX_EVIDENCE_CHARS:
            evidence_json = evidence_json[:_MAX_EVIDENCE_CHARS] + "...(truncated)"

        return (
            "Please review this MCP security scan finding and decide "
            "whether the heuristic verdict is correct.\n\n"
            f"Attack: {result.attack_name}\n"
            f"Stage: {result.stage.value}\n"
            f"Target tool: {result.target_tool}\n"
            f"Heuristic verdict: {result.verdict.value}\n"
            f"Heuristic rationale: {result.rationale}\n"
            f"Evidence: {evidence_json}\n\n"
            "Return JSON with two keys: 'verdict' (one of 'success', "
            "'failure', 'uncertain') and 'rationale' (a short explanation, "
            "max 300 characters)."
        )


_SYSTEM_PROMPT = (
    "You are a security-focused LLM judge for MCP-Strike, a tool that tests "
    "MCP (Model Context Protocol) servers for vulnerabilities. Your job is "
    "to confirm or correct a heuristic verdict on whether a specific "
    "vulnerability was detected.\n\n"
    "- 'success' means the vulnerability IS present (the attack worked).\n"
    "- 'failure' means the vulnerability is NOT present (clean tool).\n"
    "- 'uncertain' means the evidence doesn't conclusively show either.\n\n"
    "Respond ONLY with the requested JSON. Do not echo the input."
)

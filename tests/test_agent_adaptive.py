"""Unit tests for the AdaptiveAgent.

Same fake-client pattern as ``test_judge_openai.py`` — we mimic the bits
of ``openai.AsyncOpenAI`` that the agent actually touches and feed it a
queue of canned responses, then assert on what the agent did.

A separate end-to-end test against the demo server lives in
``test_cli.py``; this file is for unit-level behavior.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock

import pytest

from mcp_strike.agent.adaptive import ATTACK_NAME, AdaptiveAgent
from mcp_strike.attacks import Verdict
from mcp_strike.target import ToolInfo

# --- in-memory fake of the openai SDK's response shape ----------------------


@dataclass
class _FakeMessage:
    content: str


@dataclass
class _FakeChoice:
    message: _FakeMessage


@dataclass
class _FakeResponse:
    choices: list[_FakeChoice]


class _FakeCompletions:
    """Returns canned responses from a queue, one per ``.create()`` call."""

    def __init__(self, responses: list[str]) -> None:
        # Reverse so we can pop from the back cheaply.
        self._queue = list(reversed(responses))
        self.calls: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> _FakeResponse:
        self.calls.append(kwargs)
        if not self._queue:
            # Tests should always queue enough responses; if not, fail loudly.
            raise RuntimeError("fake openai ran out of queued responses")
        content = self._queue.pop()
        return _FakeResponse(choices=[_FakeChoice(message=_FakeMessage(content=content))])


class _FakeOpenAI:
    """Drop-in stand-in for ``openai.AsyncOpenAI``."""

    def __init__(self, responses: list[str]) -> None:
        self._completions = _FakeCompletions(responses)
        self.chat = type("_Chat", (), {"completions": self._completions})()

    @property
    def calls(self) -> list[dict[str, Any]]:
        return self._completions.calls


# --- helpers ----------------------------------------------------------------


def _tool(
    name: str = "demo_tool",
    description: str = "demo description",
    input_schema: dict[str, Any] | None = None,
) -> ToolInfo:
    return ToolInfo(
        name=name,
        description=description,
        input_schema=input_schema or {"type": "object", "properties": {}},
    )


def _target_returning(text: str) -> Any:
    """Build a fake Target whose ``call_tool`` returns a TextContent-shaped response."""

    @dataclass
    class _Block:
        text: str

    @dataclass
    class _CallResult:
        content: list[_Block]
        isError: bool = False  # noqa: N815  (mimic MCP's field name)

    target = type("_Target", (), {})()
    target.call_tool = AsyncMock(return_value=_CallResult(content=[_Block(text=text)]))  # type: ignore[attr-defined]
    return target


# --- tests ------------------------------------------------------------------


def test_early_verdict_short_circuits_loop() -> None:
    """If the LLM returns a verdict on round 1, we don't make more calls."""
    fake = _FakeOpenAI(
        responses=[
            '{"verdict": "success", "rationale": "obvious vuln", "stage": "metadata"}'
        ]
    )
    agent = AdaptiveAgent(client=fake, model="test-model", max_rounds=3, max_calls=20)

    result = asyncio.run(agent.attack_one_tool(_tool(), _target_returning("ok")))

    assert agent.calls_made == 1
    assert result.attack_name == ATTACK_NAME
    assert result.verdict == Verdict.SUCCESS
    assert result.rationale == "obvious vuln"
    # Stage classification from the LLM is honored.
    assert result.stage.value == "metadata"


def test_loops_then_final_verdict() -> None:
    """Without an early verdict, the agent loops up to max_rounds + 1 calls."""
    fake = _FakeOpenAI(
        responses=[
            # Round 1: propose
            '{"arguments": {}, "hypothesis": "test 1"}',
            # Round 2: propose
            '{"arguments": {}, "hypothesis": "test 2"}',
            # Round 3: propose
            '{"arguments": {}, "hypothesis": "test 3"}',
            # Forced final verdict (after rounds exhausted)
            '{"verdict": "failure", "rationale": "clean", "stage": "response"}',
        ]
    )
    agent = AdaptiveAgent(client=fake, model="test-model", max_rounds=3, max_calls=20)

    result = asyncio.run(agent.attack_one_tool(_tool(), _target_returning("ok")))

    assert agent.calls_made == 4  # 3 proposals + 1 final
    assert result.verdict == Verdict.FAILURE
    # History should have 3 rounds of probes recorded.
    assert len(result.evidence["history"]) == 3


def test_call_cap_is_enforced() -> None:
    """Once the per-run call cap is reached, subsequent tools get a cap-result.

    Setup: max_calls=2, max_rounds=3. First tool will use 2 calls (1 proposal,
    needs final but cap hits) and then the second tool should get
    cap-reached without any LLM call at all.
    """
    fake = _FakeOpenAI(
        responses=[
            # Tool 1, round 1
            '{"arguments": {}, "hypothesis": "h1"}',
            # Tool 1, round 2 (after this, cap is 2 so no more LLM calls)
            '{"arguments": {}, "hypothesis": "h2"}',
            # Defensive: if the agent makes more calls than expected, fail loudly.
        ]
    )
    agent = AdaptiveAgent(client=fake, model="test-model", max_rounds=3, max_calls=2)

    target = _target_returning("ok")
    results = asyncio.run(
        agent.attack_all_tools([_tool("t1"), _tool("t2")], target)
    )

    assert agent.calls_made == 2
    # Tool 1 burned through 2 calls and got a cap-reached AttackResult.
    assert results[0].target_tool == "t1"
    assert results[0].verdict == Verdict.UNCERTAIN
    assert "cap" in results[0].rationale.lower()
    # Tool 2 never went to the LLM; gets cap-reached up front.
    assert results[1].target_tool == "t2"
    assert results[1].verdict == Verdict.UNCERTAIN
    assert "cap" in results[1].rationale.lower()


def test_malformed_json_lands_on_uncertain() -> None:
    """If every LLM response is junk, the final verdict comes out UNCERTAIN."""
    fake = _FakeOpenAI(
        responses=[
            "not json at all",
            "{ partial",
            "still junk",
            "and the final one also",
        ]
    )
    agent = AdaptiveAgent(client=fake, model="test-model", max_rounds=3, max_calls=20)

    result = asyncio.run(agent.attack_one_tool(_tool(), _target_returning("ok")))

    # All 4 calls happened (3 proposals + 1 final), all returned junk →
    # verdict defaults to UNCERTAIN.
    assert agent.calls_made == 4
    assert result.verdict == Verdict.UNCERTAIN


def test_non_dict_arguments_are_recorded_and_skipped() -> None:
    """If the LLM proposes arguments that aren't a dict, we record and continue."""
    fake = _FakeOpenAI(
        responses=[
            # Round 1: bad shape (arguments is a string)
            '{"arguments": "not-a-dict", "hypothesis": "broken probe"}',
            # Round 2: propose validly so we don't have 3 broken rounds
            '{"arguments": {}, "hypothesis": "ok probe"}',
            # Round 3: propose validly
            '{"arguments": {}, "hypothesis": "another ok probe"}',
            # Forced final verdict
            '{"verdict": "failure", "rationale": "no findings", "stage": "response"}',
        ]
    )
    agent = AdaptiveAgent(client=fake, model="test-model", max_rounds=3, max_calls=20)

    result = asyncio.run(agent.attack_one_tool(_tool(), _target_returning("ok")))

    # The bad-shape round got recorded as an errored probe; history has 3 entries.
    assert len(result.evidence["history"]) == 3
    assert result.evidence["history"][0]["is_error"] is True


def test_from_env_raises_without_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """`from_env()` raises OSError when OPENAI_API_KEY is unset."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(OSError, match="OPENAI_API_KEY"):
        AdaptiveAgent.from_env()


# --- real-API integration test, gated by env --------------------------------


@pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set; skipping real-API integration test",
)
def test_against_real_openai_api() -> None:
    """End-to-end smoke against the real API. Skipped without a key.

    Uses a tiny budget so cost stays microscopic. Asserts only that we
    came back with one of the valid verdicts and that calls_made > 0.
    """
    agent = AdaptiveAgent.from_env(max_rounds=1, max_calls=3)
    result = asyncio.run(
        agent.attack_one_tool(
            _tool(
                name="get_news",
                description="Get the latest news on a topic.",
                input_schema={
                    "type": "object",
                    "properties": {"topic": {"type": "string"}},
                    "required": ["topic"],
                },
            ),
            _target_returning("normal news content, nothing suspicious"),
        )
    )
    assert agent.calls_made >= 1
    assert result.verdict in {Verdict.SUCCESS, Verdict.FAILURE, Verdict.UNCERTAIN}
    assert result.attack_name == ATTACK_NAME

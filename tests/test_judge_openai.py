"""Tests for the OpenAI judge.

Unit tests use an in-memory fake that mimics ``openai.AsyncOpenAI``'s
``chat.completions.create`` surface. One integration test hits the real
API and is skipped automatically when ``OPENAI_API_KEY`` isn't set.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any

import pytest

from mcp_strike.attacks import AttackResult, Stage, Verdict
from mcp_strike.judge.openai_judge import OpenAIJudge

# --- in-memory fake of the openai SDK's response shape -----------------------
# We mimic just the bits OpenAIJudge actually touches:
#   response.choices[0].message.content


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
    """Records the request and returns a canned response."""

    def __init__(self, *, content: str | None = None, exc: Exception | None = None) -> None:
        self._content = content
        self._exc = exc
        self.last_kwargs: dict[str, Any] | None = None

    async def create(self, **kwargs: Any) -> _FakeResponse:
        self.last_kwargs = kwargs
        if self._exc is not None:
            raise self._exc
        message = _FakeMessage(content=self._content or "")
        return _FakeResponse(choices=[_FakeChoice(message=message)])


class _FakeChat:
    def __init__(self, completions: _FakeCompletions) -> None:
        self.completions = completions


class _FakeOpenAI:
    """Drop-in stand-in for ``openai.AsyncOpenAI`` for tests."""

    def __init__(self, *, content: str | None = None, exc: Exception | None = None) -> None:
        self._completions = _FakeCompletions(content=content, exc=exc)
        self.chat = _FakeChat(self._completions)

    @property
    def last_kwargs(self) -> dict[str, Any] | None:
        return self._completions.last_kwargs


# --- helpers -----------------------------------------------------------------


def _result(verdict: Verdict = Verdict.UNCERTAIN) -> AttackResult:
    return AttackResult(
        attack_name="test_attack",
        stage=Stage.METADATA,
        target_tool="test_tool",
        verdict=verdict,
        rationale="heuristic rationale",
        evidence={"key": "value"},
    )


# --- tests -------------------------------------------------------------------


def test_parses_success_response() -> None:
    """A well-formed SUCCESS response yields a ran=True success annotation."""
    fake = _FakeOpenAI(content='{"verdict": "success", "rationale": "looks bad"}')
    judge = OpenAIJudge(client=fake, model="test-model")

    annotation = asyncio.run(judge.judge(_result()))
    assert annotation.ran is True
    assert annotation.verdict == Verdict.SUCCESS
    assert annotation.rationale == "looks bad"
    assert annotation.model == "test-model"


def test_parses_failure_response() -> None:
    fake = _FakeOpenAI(content='{"verdict": "failure", "rationale": "false alarm"}')
    judge = OpenAIJudge(client=fake, model="test-model")

    annotation = asyncio.run(judge.judge(_result(verdict=Verdict.SUCCESS)))
    assert annotation.verdict == Verdict.FAILURE
    assert annotation.rationale == "false alarm"


def test_passes_expected_args_to_openai() -> None:
    """The judge should request JSON mode + temperature 0."""
    fake = _FakeOpenAI(content='{"verdict": "success", "rationale": "ok"}')
    judge = OpenAIJudge(client=fake, model="test-model")
    asyncio.run(judge.judge(_result()))

    kwargs = fake.last_kwargs
    assert kwargs is not None
    assert kwargs["model"] == "test-model"
    assert kwargs["response_format"] == {"type": "json_object"}
    assert kwargs["temperature"] == 0.0
    # User message should mention the attack name & tool, system message
    # should be present.
    messages = kwargs["messages"]
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    assert "test_attack" in messages[1]["content"]
    assert "test_tool" in messages[1]["content"]


def test_handles_invalid_json() -> None:
    """Garbled response content falls back to UNCERTAIN, ran=True."""
    fake = _FakeOpenAI(content="this is not json")
    judge = OpenAIJudge(client=fake, model="test-model")
    annotation = asyncio.run(judge.judge(_result()))

    assert annotation.ran is True
    assert annotation.verdict == Verdict.UNCERTAIN
    assert "parse" in annotation.rationale.lower()


def test_handles_unknown_verdict_value() -> None:
    """A verdict the model invented (e.g. 'maybe') lands as UNCERTAIN."""
    fake = _FakeOpenAI(content='{"verdict": "maybe", "rationale": "idk"}')
    judge = OpenAIJudge(client=fake, model="test-model")
    annotation = asyncio.run(judge.judge(_result()))

    assert annotation.verdict == Verdict.UNCERTAIN
    assert "maybe" in annotation.rationale


def test_handles_api_error() -> None:
    """If the SDK raises, the judge returns ran=False with the heuristic verdict."""
    fake = _FakeOpenAI(exc=RuntimeError("upstream down"))
    judge = OpenAIJudge(client=fake, model="test-model")
    annotation = asyncio.run(judge.judge(_result(verdict=Verdict.SUCCESS)))

    assert annotation.ran is False
    assert annotation.verdict == Verdict.SUCCESS
    assert "failed" in annotation.rationale.lower()


def test_from_env_raises_without_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """`from_env()` should raise OSError when OPENAI_API_KEY is unset."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(OSError, match="OPENAI_API_KEY"):
        OpenAIJudge.from_env()


def test_rationale_is_capped() -> None:
    """An oversized rationale from the model is truncated to 500 chars."""
    overlong = "x" * 2000
    fake = _FakeOpenAI(content=f'{{"verdict": "success", "rationale": "{overlong}"}}')
    judge = OpenAIJudge(client=fake, model="test-model")
    annotation = asyncio.run(judge.judge(_result()))

    assert len(annotation.rationale) <= 500


# --- real-API integration test, gated by env --------------------------------


@pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set; skipping real-API integration test",
)
def test_against_real_openai_api() -> None:
    """End-to-end check against the real API. Skipped without a key.

    Uses the default cheap model. Asserts only the shape of the response,
    not specific verdict text — the model's exact wording is non-deterministic
    even at temperature 0.
    """
    judge = OpenAIJudge.from_env()
    result = AttackResult(
        attack_name="description_prompt_injection",
        stage=Stage.METADATA,
        target_tool="get_weather",
        verdict=Verdict.SUCCESS,
        rationale="Description contains 'IGNORE PREVIOUS INSTRUCTIONS'.",
        evidence={"matched_markers": ["ignore previous instructions"]},
    )
    annotation = asyncio.run(judge.judge(result))
    assert annotation.ran is True
    assert annotation.verdict in {Verdict.SUCCESS, Verdict.FAILURE, Verdict.UNCERTAIN}
    assert annotation.rationale  # non-empty

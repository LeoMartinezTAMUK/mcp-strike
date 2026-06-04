"""Tests for the pydantic config models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mcp_strike.config import RunConfig, TargetConfig


def test_target_config_minimal() -> None:
    """A minimal TargetConfig only needs `command`; other fields default."""
    cfg = TargetConfig(command="python")
    assert cfg.transport == "stdio"
    assert cfg.command == "python"
    assert cfg.args == []
    assert cfg.env is None
    # Per-call timeout has a sane default.
    assert cfg.call_timeout == 30.0


def test_target_config_full() -> None:
    cfg = TargetConfig(
        transport="stdio",
        command="python",
        args=["-m", "mcp_strike.demo_server"],
        env={"FOO": "bar"},
        call_timeout=5.0,
    )
    assert cfg.args == ["-m", "mcp_strike.demo_server"]
    assert cfg.env == {"FOO": "bar"}
    assert cfg.call_timeout == 5.0


def test_target_config_rejects_unknown_transport() -> None:
    """Only stdio is supported; unknown transport must be rejected."""
    with pytest.raises(ValidationError):
        # The type: ignore is fine; we're deliberately passing an invalid
        # literal to exercise pydantic's validation.
        TargetConfig(transport="grpc", command="python")  # type: ignore[arg-type]


def test_run_config_defaults() -> None:
    cfg = RunConfig()
    assert cfg.attacks is None
    assert cfg.show_responsible_use_notice is True
    # Judge fields default to "auto" / library defaults.
    assert cfg.judge_enabled is None  # None = auto-detect
    assert cfg.judge_model is None
    assert cfg.max_llm_calls == 20
    # Adaptive-agent fields default to "auto" / library defaults.
    assert cfg.agent_enabled is None
    assert cfg.agent_model is None
    assert cfg.agent_max_rounds == 3
    assert cfg.max_agent_calls == 50


def test_run_config_with_attack_filter() -> None:
    cfg = RunConfig(attacks=["description_prompt_injection"])
    assert cfg.attacks == ["description_prompt_injection"]


def test_run_config_judge_fields_round_trip() -> None:
    """Judge fields accept explicit values and round-trip cleanly."""
    cfg = RunConfig(
        judge_enabled=True,
        judge_model="gpt-4o",
        max_llm_calls=5,
    )
    assert cfg.judge_enabled is True
    assert cfg.judge_model == "gpt-4o"
    assert cfg.max_llm_calls == 5


def test_run_config_agent_fields_round_trip() -> None:
    """Adaptive-agent fields accept explicit values and round-trip cleanly."""
    cfg = RunConfig(
        agent_enabled=True,
        agent_model="gpt-4o",
        agent_max_rounds=5,
        max_agent_calls=10,
    )
    assert cfg.agent_enabled is True
    assert cfg.agent_model == "gpt-4o"
    assert cfg.agent_max_rounds == 5
    assert cfg.max_agent_calls == 10

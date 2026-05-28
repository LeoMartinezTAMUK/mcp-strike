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


def test_target_config_full() -> None:
    cfg = TargetConfig(
        transport="stdio",
        command="python",
        args=["-m", "demo_server"],
        env={"FOO": "bar"},
    )
    assert cfg.args == ["-m", "demo_server"]
    assert cfg.env == {"FOO": "bar"}


def test_target_config_rejects_unknown_transport() -> None:
    """Phase 1 only knows stdio; unknown transport must be rejected."""
    with pytest.raises(ValidationError):
        # The type: ignore is fine — we're deliberately passing an invalid
        # literal to exercise pydantic's validation.
        TargetConfig(transport="grpc", command="python")  # type: ignore[arg-type]


def test_run_config_defaults() -> None:
    cfg = RunConfig()
    assert cfg.attacks is None
    assert cfg.show_responsible_use_notice is True


def test_run_config_with_attack_filter() -> None:
    cfg = RunConfig(attacks=["description_prompt_injection"])
    assert cfg.attacks == ["description_prompt_injection"]

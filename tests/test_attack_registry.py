"""Tests for the attack registry plumbing.

The registry is a module-level dict mutated at decoration time. Tests use
unique class names so cross-test pollution is minimized, and clean up after
themselves where they can.
"""

from __future__ import annotations

import pytest

from mcp_strike.attacks.base import AttackResult, BaseAttack, Stage, Verdict
from mcp_strike.attacks.registry import (
    get_all_attacks,
    get_attack,
    register_attack,
    unregister_for_testing,
)
from mcp_strike.target import Target


def test_register_and_lookup() -> None:
    """A registered attack class shows up in get_all_attacks() and get_attack()."""

    @register_attack
    class _DummyAttackA(BaseAttack):
        name = "test_registry_dummy_a"
        stage = Stage.METADATA

        async def execute(self, target: Target) -> list[AttackResult]:
            return []

    try:
        names = [cls.name for cls in get_all_attacks()]
        assert "test_registry_dummy_a" in names
        assert get_attack("test_registry_dummy_a") is _DummyAttackA
    finally:
        # Don't leak the dummy into other tests.
        unregister_for_testing("test_registry_dummy_a")


def test_duplicate_name_rejected() -> None:
    """Registering two attacks under the same name must raise."""

    @register_attack
    class _DupA(BaseAttack):
        name = "test_registry_dup"
        stage = Stage.METADATA

        async def execute(self, target: Target) -> list[AttackResult]:
            return []

    try:
        with pytest.raises(ValueError, match="already registered"):

            @register_attack
            class _DupB(BaseAttack):
                name = "test_registry_dup"
                stage = Stage.METADATA

                async def execute(self, target: Target) -> list[AttackResult]:
                    return []
    finally:
        unregister_for_testing("test_registry_dup")


def test_empty_name_rejected() -> None:
    """An attack class that forgot to set `name` must be rejected."""

    with pytest.raises(ValueError, match="non-empty"):

        @register_attack
        class _NoName(BaseAttack):
            # Inherits `name = ""` from BaseAttack.
            stage = Stage.METADATA

            async def execute(self, target: Target) -> list[AttackResult]:
                return []


def test_attack_result_dataclass() -> None:
    """Sanity check on AttackResult construction + defaults."""
    result = AttackResult(
        attack_name="x",
        stage=Stage.METADATA,
        target_tool="t",
        verdict=Verdict.SUCCESS,
        rationale="why",
    )
    assert result.verdict == Verdict.SUCCESS
    assert result.evidence == {}  # default factory produces empty dict

"""Decorator-based attack registry.

Attack modules call :func:`register_attack` at import time to make themselves
discoverable. The package ``mcp_strike.attacks`` imports each concrete
attack module from its ``__init__``, populating the registry as a side
effect of importing the package.
"""

from __future__ import annotations

from typing import TypeVar

from mcp_strike.attacks.base import BaseAttack

# Module-level registry: maps each attack's `name` to its class.
# Private by convention; tests may touch it for isolation but production code
# should go through the helper functions below.
_REGISTRY: dict[str, type[BaseAttack]] = {}

T = TypeVar("T", bound=type[BaseAttack])


def register_attack(cls: T) -> T:
    """Class decorator that adds ``cls`` to the global attack registry.

    Returns the class unchanged so it can be used as a decorator:

        @register_attack
        class MyAttack(BaseAttack):
            name = "my_attack"
            ...

    Raises:
        ValueError: If ``cls.name`` is empty, or if another attack is
        already registered under the same name (likely a copy/paste bug).
    """
    if not cls.name:
        raise ValueError(f"{cls.__name__} must set a non-empty `name`")
    if cls.name in _REGISTRY:
        existing = _REGISTRY[cls.name].__name__
        raise ValueError(
            f"Attack name {cls.name!r} is already registered by {existing}"
        )
    _REGISTRY[cls.name] = cls
    return cls


def get_all_attacks() -> list[type[BaseAttack]]:
    """Return every registered attack class, ordered by name (stable for reports)."""
    return [_REGISTRY[name] for name in sorted(_REGISTRY)]


def get_attack(name: str) -> type[BaseAttack]:
    """Look up an attack class by name. Raises KeyError if unknown."""
    return _REGISTRY[name]


def unregister_for_testing(name: str) -> type[BaseAttack] | None:
    """Remove a registered attack class. **Test-only API.**

    The registry is global module-level state. Tests that register dummy
    attack subclasses via :func:`register_attack` should call this in their
    ``finally`` block to keep cross-test state hygienic. Production code
    should never call this; attack registration is meant to be permanent
    for the life of the process.

    Returns the previously-registered class, or ``None`` if no entry
    existed under that name.
    """
    return _REGISTRY.pop(name, None)

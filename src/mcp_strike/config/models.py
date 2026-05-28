"""Pydantic configuration models for MCP-Strike.

Phase 1 only needs two: how to connect to a target, and which knobs apply
to a single scan run. Both are deliberately small — every field that lands
here is one I can explain in a sentence.

Secrets live in environment variables, never in these models (see CLAUDE.md).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class TargetConfig(BaseModel):
    """How to connect to the MCP server under test.

    Phase 1 supports only the stdio transport. HTTP/SSE arrive in a later
    phase (see docs/PLAN.md §6); when they do, ``transport`` will gain
    additional ``Literal`` options and the relevant fields will become
    optional/conditional.
    """

    # Locked to "stdio" for Phase 1. Declared as a Literal so pydantic will
    # reject unknown transports at validation time.
    transport: Literal["stdio"] = "stdio"

    # The executable to launch (e.g. ``"python"``). Required.
    command: str

    # Arguments passed to ``command`` (e.g. ``["-m", "demo_server"]``).
    args: list[str] = Field(default_factory=list)

    # Optional environment for the subprocess. ``None`` means "let the MCP
    # SDK provide a minimal default environment" — that's the right default
    # for testing the demo server.
    env: dict[str, str] | None = None


class RunConfig(BaseModel):
    """Knobs for a single scan run.

    Intentionally minimal in Phase 1. We'll add per-attack settings (timeouts,
    payload overrides, etc.) as the attack library grows.
    """

    # When ``None``, every registered attack runs. When set, only attacks
    # whose ``name`` appears in this list run. Useful for ``--only=...`` and
    # for testing individual attacks in isolation.
    attacks: list[str] | None = None

    # The CLI prints a responsible-use notice at startup unless this is
    # ``False``. Defaulting to True keeps the ethics framing in front of
    # every user (see CLAUDE.md / PLAN.md §14).
    show_responsible_use_notice: bool = True

"""Attack base classes and result types.

Each attack subclasses :class:`BaseAttack`, sets ``name`` + ``stage`` as
class attributes, and implements :meth:`BaseAttack.execute`. It returns one
:class:`AttackResult` per inspected target component (per tool, typically).

The interface is uniform for passive (metadata-only) and active (tool-calling)
attacks — both kinds receive a :class:`Target` and produce a list of results.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mcp_strike.target import Target


class Stage(str, Enum):
    """MCP pipeline stage an attack targets (see docs/PLAN.md §7).

    The value is the short string used in reports; the str-Enum base keeps
    comparisons and serialization cheap.
    """

    METADATA = "metadata"        # Stage 1 — tool signature / description
    PARAMETERS = "parameters"    # Stage 2 — tool invocation / args
    RESPONSE = "response"        # Stage 3 — tool response handling (Phase 2+)


class Verdict(str, Enum):
    """Outcome of running one attack against one target component."""

    SUCCESS = "success"          # Vulnerability confirmed.
    FAILURE = "failure"          # No vulnerability detected.
    UNCERTAIN = "uncertain"      # Heuristic couldn't decide; flag for review.


@dataclass
class AttackResult:
    """The outcome of one attack against one target component.

    Convention: one AttackResult per tool inspected. An attack with no
    findings against a tool still emits a ``FAILURE`` result so reports can
    show "we looked at this tool and found nothing".
    """

    attack_name: str             # Matches BaseAttack.name. Useful in reports.
    stage: Stage                 # Matches BaseAttack.stage.
    target_tool: str             # Name of the tool that was inspected/invoked.
    verdict: Verdict
    rationale: str               # Short human-readable explanation.
    # Optional structured evidence — e.g. matched substrings, payloads tried.
    # Attacks are responsible for keeping this small so reports stay readable.
    evidence: dict[str, Any] = field(default_factory=dict)


class BaseAttack(abc.ABC):
    """Abstract base for attack modules.

    Subclasses set ``name`` and ``stage`` as class attributes and implement
    :meth:`execute`. Register the subclass via
    :func:`mcp_strike.attacks.registry.register_attack` so the CLI can find it.
    """

    #: Short, unique identifier. Used in reports and as a CLI filter.
    name: str = ""
    #: Pipeline stage this attack targets.
    stage: Stage = Stage.METADATA

    # `prepare` is deliberately a concrete no-op, not abstract — subclasses
    # only need to override it when they have setup that doesn't depend on
    # the target. Ruff's B027 ("empty method on ABC") fires here because it
    # can't know that, so we suppress it with intent stated in the docstring.
    def prepare(self) -> None:  # noqa: B027
        """Optional setup hook that doesn't need the target.

        Default: no-op. Override when an attack needs to compile payloads or
        load fixtures before reaching the target. Listed in docs/PLAN.md §6
        as part of the attack interface.
        """

    @abc.abstractmethod
    async def execute(self, target: Target) -> list[AttackResult]:
        """Run the attack against ``target`` and return all findings.

        Returns ``[]`` when there's nothing to report (e.g. the target has
        no tools the attack applies to). Network/protocol exceptions should
        be wrapped in an ``UNCERTAIN`` AttackResult rather than raised — a
        single failed probe shouldn't abort the whole scan.
        """

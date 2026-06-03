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
    """MCP pipeline stage an attack targets.

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


# Maximum length of the ``rationale`` string in a :class:`JudgeAnnotation`
# produced by an LLM (judge or agent). Caps prompt-blowback into terminal
# reports and JSON output. Both ``OpenAIJudge`` and ``AdaptiveAgent``
# truncate to this length when constructing the annotation.
LLM_RATIONALE_MAX_CHARS = 500


@dataclass
class JudgeAnnotation:
    """An LLM judge's opinion on an AttackResult.

    Produced by :class:`mcp_strike.judge.BaseJudge` implementations and
    attached to :attr:`AttackResult.judge` by the scan pipeline. Lives next
    to AttackResult (as data) so the judge module can depend on attacks
    one-way without a circular import.
    """

    # The judge's verdict. May agree with or override the heuristic verdict.
    verdict: Verdict
    # Short human-readable explanation from the judge.
    rationale: str
    # Model name that produced this opinion. Empty string when the judge
    # didn't actually run (e.g. NullJudge, or the call cap was reached).
    model: str
    # ``False`` when the judge was disabled or capped out; ``True`` when an
    # LLM call actually happened.
    ran: bool


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
    # Optional judge opinion. ``None`` until the scan pipeline runs a judge
    # over this result (and possibly even after, if the judge was disabled
    # or skipped this row).
    judge: JudgeAnnotation | None = None


class BaseAttack(abc.ABC):
    """Abstract base for attack modules.

    Subclasses set ``name`` and ``stage`` as class attributes and implement
    :meth:`execute`. Register the subclass via
    :func:`mcp_strike.attacks.registry.register_attack` so the CLI can find it.

    Note: an earlier draft of this interface also included a ``prepare()``
    hook. We dropped it during Phase 4 polish — every concrete attack
    either does its setup at module import time or doesn't need any. If a
    future attack needs target-independent setup, add the hook back rather
    than abusing ``__init__`` for it.
    """

    #: Short, unique identifier. Used in reports and as a CLI filter.
    name: str = ""
    #: Pipeline stage this attack targets.
    stage: Stage = Stage.METADATA

    @abc.abstractmethod
    async def execute(self, target: Target) -> list[AttackResult]:
        """Run the attack against ``target`` and return all findings.

        Returns ``[]`` when there's nothing to report (e.g. the target has
        no tools the attack applies to). Network/protocol exceptions should
        be wrapped in an ``UNCERTAIN`` AttackResult rather than raised — a
        single failed probe shouldn't abort the whole scan.
        """

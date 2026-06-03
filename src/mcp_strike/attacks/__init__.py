"""Attack modules.

Importing this package imports every concrete attack, which causes each
attack class to register itself with the module-level registry (via the
``@register_attack`` decorator). After importing this package, callers can
use :func:`get_all_attacks` to discover what's available.

The imports below are isort-sorted. The submodule imports
(``description_injection`` et al.) are kept for their *side effect* —
their module bodies decorate each attack class with ``@register_attack``
at import time, populating the registry. The order of those imports
doesn't matter; the registry stores by name.

Attacks are organized by MCP pipeline stage: metadata (description /
schema inspection), parameters (active tool-call probing), and response
(active probing + response inspection).
"""

from mcp_strike.attacks import (  # noqa: F401  (imported for side effects)
    data_exfiltration,
    description_injection,
    overreaching_parameters,
    path_traversal,
    response_injection,
)
from mcp_strike.attacks.base import (
    AttackResult,
    BaseAttack,
    JudgeAnnotation,
    Stage,
    Verdict,
)
from mcp_strike.attacks.registry import (
    get_all_attacks,
    get_attack,
    register_attack,
)

__all__ = [
    "AttackResult",
    "BaseAttack",
    "JudgeAnnotation",
    "Stage",
    "Verdict",
    "get_all_attacks",
    "get_attack",
    "register_attack",
]

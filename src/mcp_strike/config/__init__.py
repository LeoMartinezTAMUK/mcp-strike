"""Configuration models for MCP-Strike (see docs/PLAN.md §6).

Re-exports the public types so callers can write::

    from mcp_strike.config import RunConfig, TargetConfig
"""

from mcp_strike.config.models import RunConfig, TargetConfig

__all__ = ["RunConfig", "TargetConfig"]

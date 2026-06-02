"""MCP-Strike — active, runtime adversarial testing for MCP servers.

This top-level package is intentionally thin. Components live in subpackages
(see docs/PLAN.md §6 for the architecture).
"""

from importlib.metadata import PackageNotFoundError, version

try:
    # Single source of truth: pyproject.toml's [project] version, surfaced
    # via the installed package metadata. Works after `pip install` or
    # `uv sync` (editable install).
    __version__ = version("mcp-strike")
except PackageNotFoundError:
    # The package isn't installed (e.g. running straight from a clone with
    # nothing on PYTHONPATH but the src layout). Fall back so importing
    # the package never raises.
    __version__ = "0.0.0+dev"

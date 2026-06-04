"""MCP-Strike: active, runtime adversarial testing for MCP servers.

This top-level package is intentionally thin. Components live in subpackages:
``client`` (stdio transport), ``target`` (normalized session), ``attacks``
(BaseAttack + concrete attacks), ``judge`` (LLM-as-judge), ``agent``
(adaptive attacker), ``report`` (terminal + JSON), ``config`` (pydantic
models + .env loader), ``cli`` (typer entry point), and ``demo_server``
(bundled vulnerable test target).
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

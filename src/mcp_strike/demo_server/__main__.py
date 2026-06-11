"""Entry point so the server can be launched as ``python -m mcp_strike.demo_server``.

We isolate this from ``server.py`` so importing the server module (e.g.
from a test) doesn't accidentally start the stdio event loop.
"""

import logging
import sys

from mcp_strike.demo_server.server import build_server


def main() -> None:
    """Run the demo MCP server on stdio. Blocks until the client disconnects."""
    # FastMCP / the MCP SDK log INFO-level "Processing request" lines to
    # stderr by default. Useful when developing the SDK, noise when the demo
    # is being used as an attack target. Floor the SDK loggers at WARNING.
    # Scoped to this entry point so it doesn't affect anything else that
    # imports the demo server (e.g. tests, which need predictable logging).
    logging.getLogger("mcp").setLevel(logging.WARNING)

    # If a human launched this directly in a terminal (rather than mcp-strike
    # spawning it over a pipe), make the danger obvious. Guarded on isatty so
    # it never clutters a normal `mcp-strike demo` run, where this process's
    # stderr is a pipe back to the scanner.
    if sys.stderr.isatty():
        print(
            "WARNING: this is the MCP-Strike demo server. It is DELIBERATELY "
            "VULNERABLE (arbitrary file read, planted prompt injections). "
            "Never expose it to anything you care about.",
            file=sys.stderr,
        )

    server = build_server()
    # FastMCP.run() defaults to the stdio transport when none is specified.
    server.run()


if __name__ == "__main__":
    main()

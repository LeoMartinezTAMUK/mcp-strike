"""Entry point so the server can be launched as ``python -m demo_server``.

We isolate this from ``server.py`` so importing the server (e.g. from a test)
doesn't accidentally start the stdio event loop.
"""

import logging

from demo_server.server import build_server


def main() -> None:
    """Run the demo MCP server on stdio. Blocks until the client disconnects."""
    # FastMCP / the MCP SDK log INFO-level "Processing request" lines to
    # stderr by default. Useful when developing the SDK, noise when the demo
    # is being used as an attack target. Floor the SDK loggers at WARNING.
    # Scoped to this entry point so it doesn't affect anything else that
    # imports the demo server (e.g. tests, which need predictable logging).
    logging.getLogger("mcp").setLevel(logging.WARNING)

    server = build_server()
    # FastMCP.run() defaults to the stdio transport when none is specified.
    server.run()


if __name__ == "__main__":
    main()

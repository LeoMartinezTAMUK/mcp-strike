"""Minimal `.env` file loader.

We deliberately don't pull in ``python-dotenv``: a tiny manual parser is
easier to read, has zero new dependencies, and covers our only use case
(``KEY=VALUE`` lines such as ``OPENAI_API_KEY=...``).

The loader is intentionally restrictive:

- One ``KEY=VALUE`` per line.
- Optional single or double quotes around the value (stripped on read).
- Lines starting with ``#`` (ignoring leading whitespace) are comments.
- Blank lines are skipped.
- **Existing environment variables are NOT overridden.** This means a
  shell ``export FOO=...`` always wins over the file, which is the
  intuitive precedence.

NOT supported: multiline values, escape sequences, ``$VAR`` interpolation,
``export`` prefix. If any of those become necessary, switch to
``python-dotenv`` and add it as a declared dependency.
"""

from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: Path) -> int:
    """Read ``path`` (a .env-style file) and populate ``os.environ``.

    Args:
        path: Filesystem path to a .env file. If the file doesn't exist,
            the function is a no-op (returns 0), so callers don't need
            to guard the call.

    Returns:
        The number of keys actually set into the environment (excludes
        keys that were already present, and lines that didn't parse).
    """
    if not path.exists():
        return 0

    set_count = 0
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        # Blank lines and comments are ignored.
        if not line or line.startswith("#"):
            continue

        # We need a `=` to split key from value; silently skip otherwise.
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        # Strip a balanced pair of surrounding quotes, single or double.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]

        # Empty key is malformed; existing env wins.
        if not key or key in os.environ:
            continue

        os.environ[key] = value
        set_count += 1

    return set_count

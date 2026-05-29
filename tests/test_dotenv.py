"""Tests for the minimal .env loader."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mcp_strike.config.dotenv import load_dotenv


def test_no_op_when_file_missing(tmp_path: Path) -> None:
    """A non-existent path should return 0 and not raise."""
    assert load_dotenv(tmp_path / "missing.env") == 0


def test_loads_basic_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Each KEY=VALUE line populates os.environ when the key isn't set."""
    monkeypatch.delenv("DOTENV_TEST_A", raising=False)
    monkeypatch.delenv("DOTENV_TEST_B", raising=False)

    env_path = tmp_path / ".env"
    env_path.write_text(
        "DOTENV_TEST_A=value-a\n"
        "DOTENV_TEST_B=value-b\n"
    )

    count = load_dotenv(env_path)
    assert count == 2
    assert os.environ["DOTENV_TEST_A"] == "value-a"
    assert os.environ["DOTENV_TEST_B"] == "value-b"


def test_strips_quotes_around_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Single and double quotes around the value are stripped."""
    monkeypatch.delenv("DOTENV_TEST_SINGLE", raising=False)
    monkeypatch.delenv("DOTENV_TEST_DOUBLE", raising=False)

    env_path = tmp_path / ".env"
    env_path.write_text(
        'DOTENV_TEST_SINGLE=\'single\'\n'
        'DOTENV_TEST_DOUBLE="double"\n'
    )

    load_dotenv(env_path)
    assert os.environ["DOTENV_TEST_SINGLE"] == "single"
    assert os.environ["DOTENV_TEST_DOUBLE"] == "double"


def test_skips_comments_and_blanks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Comment lines and blank lines are ignored."""
    monkeypatch.delenv("DOTENV_TEST_C", raising=False)

    env_path = tmp_path / ".env"
    env_path.write_text(
        "# this is a comment\n"
        "\n"
        "DOTENV_TEST_C=value-c\n"
        "  # indented comment also skipped\n"
    )

    count = load_dotenv(env_path)
    assert count == 1
    assert os.environ["DOTENV_TEST_C"] == "value-c"


def test_does_not_override_existing_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Shell-exported env wins over the file (returns 0; var unchanged)."""
    monkeypatch.setenv("DOTENV_TEST_PRECEDENCE", "shell-value")

    env_path = tmp_path / ".env"
    env_path.write_text("DOTENV_TEST_PRECEDENCE=file-value\n")

    count = load_dotenv(env_path)
    assert count == 0
    assert os.environ["DOTENV_TEST_PRECEDENCE"] == "shell-value"


def test_skips_lines_without_equals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A junk line without `=` is silently ignored (doesn't crash)."""
    monkeypatch.delenv("DOTENV_TEST_OK", raising=False)

    env_path = tmp_path / ".env"
    env_path.write_text(
        "this is not a valid line\n"
        "DOTENV_TEST_OK=ok\n"
    )

    count = load_dotenv(env_path)
    assert count == 1
    assert os.environ["DOTENV_TEST_OK"] == "ok"

"""Tests for the typer CLI.

Uses ``typer.testing.CliRunner`` to invoke the app in-process. Each invoke
call runs the relevant command function synchronously (the async
target-and-scan inside is bridged with ``asyncio.run``).

The ``demo`` tests launch the deliberately-vulnerable demo server as a
subprocess and exercise the full scan-and-render path end to end. We pass
``--no-judge --no-agent`` to keep them hermetic: even when an
``OPENAI_API_KEY`` happens to be in the developer's env, the LLM
features stay off and the tests don't make real API calls.

The single real-API agent test at the bottom of this file is the
exception — it's gated on ``OPENAI_API_KEY`` and skipped otherwise.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_strike.cli import app

runner = CliRunner()


def test_list_attacks_shows_every_registered_attack() -> None:
    """`list-attacks` should mention every attack registered so far."""
    result = runner.invoke(app, ["list-attacks"])
    assert result.exit_code == 0, result.output
    # Phase 1 attacks.
    assert "description_prompt_injection" in result.stdout
    assert "overreaching_parameters" in result.stdout
    assert "path_traversal_probe" in result.stdout
    # Phase 2 attacks.
    assert "response_injection_probe" in result.stdout
    assert "data_exfiltration_probe" in result.stdout


def test_demo_runs_and_surfaces_planted_vulns() -> None:
    """`demo --no-notice --no-judge --no-agent` runs a full static scan.

    --no-notice keeps output tight; --no-judge + --no-agent skip any
    OpenAI calls so the test is hermetic. We don't grep for specific
    rationales — those may evolve — just for the verdict label and an
    attack name.
    """
    result = runner.invoke(
        app, ["demo", "--no-notice", "--no-judge", "--no-agent"]
    )
    assert result.exit_code == 0, result.output
    assert "SUCCESS" in result.stdout
    assert "description_prompt_injection" in result.stdout


def test_demo_json_output_is_valid_json() -> None:
    """`demo --json --no-judge --no-agent` emits parseable JSON to stdout.

    Asserts top-level schema only — we trust the schema tests in
    test_report_json.py for finer-grained checks.
    """
    result = runner.invoke(
        app, ["demo", "--json", "--no-judge", "--no-agent"]
    )
    assert result.exit_code == 0, result.output

    parsed = json.loads(result.stdout)
    assert "summary" in parsed
    assert "results" in parsed
    summary = parsed["summary"]
    assert summary["total"] == len(parsed["results"])
    # With --no-judge + --no-agent, both feature blocks should be null.
    assert summary["llm_calls_used"] is None
    assert summary["llm_calls_cap"] is None
    assert summary["agent_calls_used"] is None
    assert summary["agent_calls_cap"] is None
    # At least one SUCCESS from the planted static vulns.
    assert summary["success"] >= 1


def test_demo_json_judge_metadata_when_disabled() -> None:
    """With --no-judge, no row should claim a real LLM call happened.

    Important nuance: ``--no-judge`` doesn't make ``judge`` always-null.
    The judge pipeline still runs NullJudge over UNCERTAIN/SUCCESS rows
    (FAILURE rows are skipped to save calls). NullJudge attaches a
    ``ran=False`` annotation so consumers can distinguish three states:

    - ``judge: null``                          → row wasn't eligible (FAILURE)
    - ``judge: {..., "ran": false}``           → eligible but judge disabled
    - ``judge: {..., "ran": true}``            → real LLM call happened
    """
    result = runner.invoke(
        app, ["demo", "--json", "--no-judge", "--no-agent"]
    )
    parsed = json.loads(result.stdout)
    for row in parsed["results"]:
        judge = row["judge"]
        if row["verdict"] == "failure":
            # FAILURE rows are skipped by the cost-saving policy.
            assert judge is None, f"unexpected judge on FAILURE row: {row}"
        else:
            # SUCCESS / UNCERTAIN rows get a NullJudge annotation with ran=False.
            assert judge is not None, f"missing judge annotation on {row}"
            assert judge["ran"] is False, f"unexpected ran=True with --no-judge: {row}"


def test_demo_output_file_writes_json_to_disk(tmp_path: Path) -> None:
    """`--output-file PATH` writes the JSON report to disk."""
    out_path = tmp_path / "scan.json"
    result = runner.invoke(
        app,
        ["demo", "--no-judge", "--no-agent", "--output-file", str(out_path)],
    )
    assert result.exit_code == 0, result.output

    text = out_path.read_text(encoding="utf-8")
    parsed = json.loads(text)
    assert "summary" in parsed
    assert parsed["summary"]["total"] >= 1


def test_scan_rejects_unknown_attack_name() -> None:
    """`scan --only no_such_attack ...` exits non-zero with a clear error."""
    result = runner.invoke(
        app,
        [
            "scan",
            "--command", "python",
            "--arg", "-m",
            "--arg", "demo_server",
            "--only", "no_such_attack",
            "--no-judge",
            "--no-agent",
        ],
    )
    assert result.exit_code != 0
    assert "no_such_attack" in result.output


def test_root_help_lists_subcommands() -> None:
    """Bare invocation prints help (no_args_is_help=True) and lists subcommands."""
    result = runner.invoke(app, [])
    # `no_args_is_help` produces exit code 0 in recent typer; older versions
    # may use 2. Either is acceptable for help.
    assert result.exit_code in (0, 2)
    output = result.output
    assert "scan" in output
    assert "demo" in output
    assert "list-attacks" in output


# --- real-API integration test, gated by env -------------------------------


@pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set; skipping real-API agent test",
)
def test_demo_with_agent_catches_vuln_six() -> None:
    """End-to-end: the adaptive agent should flag check_session (VULN #6).

    Static attacks all land on FAILURE (or skip) for check_session — that's
    enforced by ``test_vuln_six_static_blindspot.py``. The agent is the
    only line of defense, and this test confirms it actually catches it.

    Cap is generous (60) so all 6 demo tools get probed; total cost is
    fractions of a cent on gpt-4o-mini.
    """
    result = runner.invoke(
        app,
        [
            "demo",
            "--no-judge",        # focus the test on the agent
            "--agent",           # force on, regardless of auto-detect
            "--json",
            "--no-notice",
            "--max-agent-calls", "60",
        ],
    )
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)

    # Find the agent's row for check_session.
    agent_rows_for_check_session = [
        r for r in parsed["results"]
        if r["attack_name"] == "adaptive_agent" and r["target_tool"] == "check_session"
    ]
    assert len(agent_rows_for_check_session) == 1, (
        "expected exactly one agent row for check_session; "
        f"got {len(agent_rows_for_check_session)}"
    )

    # The agent should NOT call this clean — it's actively asking for a
    # password. SUCCESS is ideal; UNCERTAIN is acceptable given LLM
    # non-determinism. FAILURE would mean the agent missed it.
    verdict = agent_rows_for_check_session[0]["verdict"]
    assert verdict != "failure", (
        f"agent missed VULN #6: verdict was {verdict!r}, rationale: "
        f"{agent_rows_for_check_session[0]['rationale']!r}"
    )

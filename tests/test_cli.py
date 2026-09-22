import json
import subprocess
import sys
from pathlib import Path

import pytest

from coolai.config import load, load_policy
from coolai.runtime import load_bindings
from coolai.simulator import simulate

ROOT = Path(__file__).resolve().parents[1]


def cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "coolai.cli", *map(str, args)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
    )


def test_documented_example_is_blocked_and_legacy_cli_still_works():
    result = cli("examples/send_contract.json", "--policy", "policies/default.yml")
    assert result.returncode == 3
    assert json.loads(result.stdout)["decision"] == "block"


def test_demo_proves_dispatch_counts():
    result = cli("demo")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["actual_dispatches"] == ["read_document", "send_message"]
    assert [r["executed"] for r in data["scenarios"]] == [True, False, False, True]


def test_policy_check():
    result = cli("check", "--policy", "policies/default.yml", "--bindings", "examples/bindings.yml")
    assert result.returncode == 0
    assert json.loads(result.stdout)["valid"]


def test_scenarios_and_candidate_relaxation():
    result = cli(
        "simulate",
        "examples/scenarios.json",
        "--policy",
        "policies/default.yml",
        "--bindings",
        "examples/bindings.yml",
    )
    assert result.returncode == 0, result.stderr
    result = cli(
        "simulate",
        "examples/scenarios.json",
        "--policy",
        "policies/default.yml",
        "--bindings",
        "examples/bindings.yml",
        "--compare",
        "policies/legaltech.yml",
        "--fail-on-relaxation",
    )
    assert result.returncode == 5
    data = json.loads(result.stdout)
    assert data["relaxed"] == 2
    assert data["failed_expectations"] == 2


def test_cli_invalid_input_is_structured_and_private(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"tool":"PRIVATE_BAD_TOOL","operation":7}')
    result = cli("evaluate", bad)
    assert result.returncode == 4
    assert result.stdout == ""
    assert "PRIVATE_BAD_TOOL" not in result.stderr
    assert json.loads(result.stderr)["decision"] == "block"


def test_duplicate_scenario_ids_rejected():
    case = {"id": "x", "name": "read_document", "arguments": {}}
    with pytest.raises(ValueError):
        simulate(
            [case, case],
            load_policy(ROOT / "policies/default.yml"),
            load_bindings(load(ROOT / "examples/bindings.yml")),
        )

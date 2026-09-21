"""Command line interface for inspecting proposed agent actions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from .engine import Decision, Gate, ToolCall


def load_policy(path: Path | None) -> Gate:
    if path is None:
        return Gate()
    with path.open(encoding="utf-8") as handle:
        return Gate.from_dict(yaml.safe_load(handle) or {})


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate an AI-agent tool call against coolAI Gate policy.")
    parser.add_argument("action", type=Path, help="JSON file with tool, operation, target and optional data_classes.")
    parser.add_argument("--policy", type=Path, help="YAML policy file.")
    args = parser.parse_args()

    action = ToolCall.from_dict(json.loads(args.action.read_text(encoding="utf-8")))
    result = load_policy(args.policy).evaluate(action)
    print(json.dumps(result.as_dict(), indent=2))
    raise SystemExit({Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 2, Decision.BLOCK: 3}[result.decision])


if __name__ == "__main__":
    main()

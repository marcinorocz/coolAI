"""CLI for evaluation, simulation, trusted approvals and the optional MCP bridge."""

import argparse
import asyncio
import json
import sqlite3
import sys
from pathlib import Path

from .approvals import ApprovalStore
from .audit import AuditLog
from .config import load, load_policy
from .engine import Decision, ToolCall, ValidationError, canonical, obj
from .runtime import GuardedExecutor, load_bindings
from .simulator import simulate


def parser():
    root = argparse.ArgumentParser(description="Explain and enforce AI tool policies.")
    commands = root.add_subparsers(dest="command", required=True)
    evaluate = commands.add_parser("evaluate", help="Evaluate an action description; never executes it.")
    evaluate.add_argument("action", type=Path)
    evaluate.add_argument("--policy", type=Path)
    check = commands.add_parser("check", help="Validate policy and optional trusted bindings.")
    check.add_argument("--policy", type=Path, required=True)
    check.add_argument("--bindings", type=Path)
    simulation = commands.add_parser("simulate", help="Run or compare offline policy scenarios.")
    simulation.add_argument("scenarios", type=Path)
    simulation.add_argument("--policy", type=Path, required=True)
    simulation.add_argument("--bindings", type=Path, required=True)
    simulation.add_argument("--compare", type=Path)
    simulation.add_argument("--fail-on-relaxation", action="store_true")
    commands.add_parser("demo", help="Run a local demonstration with no external effects.")
    for command in ("approve", "proxy"):
        item = commands.add_parser(command)
        item.add_argument("--policy", type=Path, required=True)
        item.add_argument("--bindings", type=Path, required=True)
        item.add_argument(
            "--upstream", type=Path, required=True, help="Trusted command/args/cwd JSON or YAML."
        )
        item.add_argument("--audit-db", type=Path, required=True)
        item.add_argument("--approval-db", type=Path)
        item.add_argument("--key-file", type=Path)
        if command == "approve":
            item.add_argument("call", type=Path, help="Exact name and arguments to approve.")
            item.add_argument("--actor", required=True)
            item.add_argument("--ttl", type=int, default=300)
            item.add_argument("--yes", action="store_true", help="Operator confirms the reviewed call.")
    return root


def run(args):
    if args.command == "demo":
        from .demo import demo

        asyncio.run(demo())
        return 0
    gate = load_policy(args.policy)
    if args.command == "evaluate":
        result = gate.evaluate(ToolCall.from_dict(load(args.action)))
        print(canonical(result.as_dict()))
        return {Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 2, Decision.BLOCK: 3}[result.decision]
    bindings = load_bindings(load(args.bindings)) if args.bindings else {}
    if args.command == "check":
        for binding in bindings.values():
            if binding.operation not in dict(gate.tools).get(binding.tool, ()):
                raise ValidationError("A binding refers to a tool/operation not registered in this policy.")
        print(canonical({"valid": True, "policy_id": gate.fingerprint, "bindings": len(bindings)}))
        return 0
    if args.command == "simulate":
        report = simulate(
            load(args.scenarios), gate, bindings, load_policy(args.compare) if args.compare else None
        )
        print(json.dumps(report, indent=2))
        return 5 if report["failed_expectations"] or (args.fail_on_relaxation and report["relaxed"]) else 0
    from .mcp_proxy import serve, upstream_config

    upstream = upstream_config(load(args.upstream))
    if bool(args.approval_db) != bool(args.key_file):
        raise ValidationError("Supply both --approval-db and --key-file, or neither.")
    approvals = ApprovalStore(args.approval_db, args.key_file.read_bytes()) if args.key_file else None
    executor = GuardedExecutor(gate, bindings, AuditLog(args.audit_db), approvals, scope=canonical(upstream))
    if args.command == "approve":
        if approvals is None or not args.yes:
            raise ValidationError("Trusted operator approval requires a key, database and --yes.")
        call = obj(load(args.call), {"name", "arguments"}, {"name", "arguments"})
        _, result = executor.prepare(call["name"], call["arguments"])
        if result.decision is not Decision.REQUIRE_APPROVAL:
            raise ValidationError("Only require_approval actions can receive an approval.")
        executor.audit.record(result, "approval_issued", "operator", args.actor)
        print(approvals.issue(result.action_id, result.policy_id, args.actor, args.ttl))
        return 0
    asyncio.run(serve(executor, upstream))
    return 0


def main():
    argv = sys.argv[1:]
    commands = {"evaluate", "check", "simulate", "demo", "approve", "proxy"}
    if argv and not argv[0].startswith("-") and argv[0] not in commands:
        argv.insert(0, "evaluate")
    try:
        code = run(parser().parse_args(argv))
    except (ValidationError, OSError, sqlite3.Error):
        print('{"error":"invalid_input_or_unavailable_state","decision":"block"}', file=sys.stderr)
        code = 4
    except ImportError:
        print('{"error":"install_coolai_gate_mcp_extra","decision":"block"}', file=sys.stderr)
        code = 4
    raise SystemExit(code)


if __name__ == "__main__":
    main()

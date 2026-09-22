"""Safe offline demonstration with real dispatch counting."""

import json
import secrets
from pathlib import Path
from tempfile import TemporaryDirectory

from .approvals import ApprovalStore
from .audit import AuditLog
from .engine import Gate
from .runtime import GateDenied, GuardedExecutor, load_bindings


async def demo():
    empty = {"type": "object", "properties": {}, "additionalProperties": False}
    bindings = load_bindings(
        {
            "read_document": {
                "tool": "document_store",
                "operation": "read",
                "target": "internal://demo/document",
                "data_classes": ["public"],
                "schema": empty,
            },
            "send_message": {
                "tool": "mailer",
                "operation": "send",
                "target_argument": "recipient",
                "data_classes": ["public"],
                "schema": {
                    "type": "object",
                    "properties": {"recipient": {"type": "string"}, "body": {"type": "string"}},
                    "required": ["recipient", "body"],
                    "additionalProperties": False,
                },
            },
            "send_secret": {
                "tool": "mailer",
                "operation": "send",
                "target": "email:outside@example.com",
                "data_classes": ["secret"],
                "schema": empty,
            },
        }
    )
    with TemporaryDirectory() as temp:
        approvals = ApprovalStore(Path(temp) / "approvals.db", secrets.token_bytes(32))
        executor = GuardedExecutor(Gate(), bindings, AuditLog(Path(temp) / "audit.db"), approvals)
        calls = []

        async def dispatch(name, arguments):
            calls.append(name)
            return {"ok": True}

        rows = []
        for name, args in (
            ("read_document", {}),
            ("send_message", {"recipient": "email:client@example.com", "body": "Hello"}),
            ("send_secret", {}),
        ):
            _, decision = executor.prepare(name, args)
            try:
                await executor.execute(name, args, dispatch)
                executed = True
            except GateDenied:
                executed = False
            rows.append({"tool": name, "decision": decision.decision.value, "executed": executed})
        args = {"recipient": "email:client@example.com", "body": "Hello"}
        _, decision = executor.prepare("send_message", args)
        token = approvals.issue(decision.action_id, decision.policy_id, "demo-operator")
        await executor.execute("send_message", args, dispatch, token)
        rows.append({"tool": "send_message", "decision": "approved_once", "executed": True})
        print(json.dumps({"scenarios": rows, "actual_dispatches": calls}, indent=2))

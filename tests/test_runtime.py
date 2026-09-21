import asyncio
import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from coolai.approvals import ApprovalError, ApprovalStore
from coolai.audit import AuditLog
from coolai.engine import Gate, ValidationError
from coolai.runtime import Binding, GateDenied, GuardedExecutor, load_bindings


@pytest.fixture
def bindings():
    return load_bindings(
        {
            "send": {
                "tool": "mailer",
                "operation": "send",
                "target_argument": "recipient",
                "data_classes": ["personal"],
                "schema": {
                    "type": "object",
                    "properties": {"recipient": {"type": "string"}, "body": {"type": "string"}},
                    "required": ["recipient", "body"],
                    "additionalProperties": False,
                },
            },
            "read": {
                "tool": "document_store",
                "operation": "read",
                "target": "internal://docs/1",
                "data_classes": ["public"],
                "schema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
        }
    )


@pytest.fixture
def executor(tmp_path, bindings):
    return GuardedExecutor(
        Gate(trusted_domains=("example.com",), external_data_classes=("personal",)),
        bindings,
        AuditLog(tmp_path / "audit.db"),
        ApprovalStore(tmp_path / "approval.db", b"x" * 32),
    )


def run(coro):
    return asyncio.run(coro)


def call():
    return {"recipient": "email:a@example.com", "body": "PRIVATE_BODY"}


def approval(executor, arguments=None):
    _, result = executor.prepare("send", arguments or call())
    return executor.approvals.issue(result.action_id, result.policy_id, "operator")


def test_blocked_and_unapproved_calls_never_reach_dispatch(executor):
    dispatched = []

    async def dispatch(name, args):
        dispatched.append(args)

    for arguments in (call(), call() | {"recipient": "email:a@evil.example"}):
        with pytest.raises(GateDenied):
            run(executor.execute("send", arguments, dispatch))
    assert dispatched == []


def test_registered_read_is_dispatched(executor):
    async def dispatch(name, args):
        assert name == "read" and args == {}
        return "ok"

    assert run(executor.execute("read", {}, dispatch)) == "ok"


def test_approval_is_bound_to_recipient_body_policy_and_scope(executor):
    token = approval(executor)
    called = []

    async def dispatch(name, args):
        called.append(args)
        return "ok"

    for changed in (call() | {"body": "changed"}, call() | {"recipient": "email:b@example.com"}):
        with pytest.raises(GateDenied):
            run(executor.execute("send", changed, dispatch, token))
    other = GuardedExecutor(
        executor.gate, executor.bindings, executor.audit, executor.approvals, scope="another-server"
    )
    with pytest.raises(GateDenied):
        run(other.execute("send", call(), dispatch, token))
    other = GuardedExecutor(
        replace(executor.gate, trusted_domains=("example.com", "other.example")),
        executor.bindings,
        executor.audit,
        executor.approvals,
    )
    with pytest.raises(GateDenied):
        run(other.execute("send", call(), dispatch, token))
    assert called == []
    assert run(executor.execute("send", call(), dispatch, token)) == "ok"
    with pytest.raises(GateDenied):
        run(executor.execute("send", call(), dispatch, token))
    assert len(called) == 1


def test_block_cannot_be_overridden_by_a_signed_token(executor):
    args = call() | {"recipient": "email:a@evil.example"}
    _, evaluation = executor.prepare("send", args)
    token = executor.approvals.issue(evaluation.action_id, evaluation.policy_id, "operator")

    async def dispatch(*_):
        pytest.fail("Blocked action reached upstream.")

    with pytest.raises(GateDenied):
        run(executor.execute("send", args, dispatch, token))


def test_replay_is_prevented_across_store_restart(tmp_path):
    path, key = tmp_path / "state.db", b"k" * 32
    store = ApprovalStore(path, key)
    token = store.issue("action", "policy", "operator")
    assert store.consume(token, "action", "policy") == "operator"
    with pytest.raises(ApprovalError):
        ApprovalStore(path, key).consume(token, "action", "policy")


def test_concurrent_approval_consumption_is_atomic(tmp_path):
    store = ApprovalStore(tmp_path / "state.db", b"k" * 32)
    token = store.issue("action", "policy", "operator")

    def consume(_):
        try:
            store.consume(token, "action", "policy")
            return True
        except ApprovalError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(consume, range(16))) == 1


def test_expired_and_tampered_tokens_are_rejected(tmp_path):
    now = [100.0]
    store = ApprovalStore(tmp_path / "state.db", b"k" * 32, clock=lambda: now[0])
    token = store.issue("action", "policy", "operator", ttl=1)
    for invalid in ("not-a-token", token[:-1] + ("0" if token[-1] != "0" else "1")):
        with pytest.raises(ApprovalError):
            store.consume(invalid, "action", "policy")
    now[0] = 101
    with pytest.raises(ApprovalError):
        store.consume(token, "action", "policy")


def test_invalid_arguments_and_metadata_spoofing_never_dispatch(executor):
    async def dispatch(*_):
        pytest.fail("Invalid arguments reached upstream.")

    for args in (
        call() | {"data_classes": ["public"]},
        call() | {"operation": "read"},
        call() | {"recipient": 3},
        {"recipient": "email:a@example.com"},
        [],
        None,
    ):
        with pytest.raises(ValidationError):
            run(executor.execute("send", args, dispatch))


def test_immutable_snapshot_prevents_argument_mutation(executor):
    original = call()
    token = approval(executor, original)

    async def dispatch(name, args):
        original["body"] = "CHANGED"
        assert args["body"] == "PRIVATE_BODY"

    run(executor.execute("send", original, dispatch, token))


def test_audit_failure_prevents_dispatch(executor):
    class BrokenAudit:
        def record(self, *args):
            raise OSError("disk full")

    executor.audit = BrokenAudit()

    async def dispatch(*args):
        pytest.fail("Audit failure reached upstream.")

    with pytest.raises(OSError):
        run(executor.execute("read", {}, dispatch))


def test_audit_excludes_payload_and_records_outcome(executor):
    token = approval(executor)

    async def dispatch(*args):
        return "PRIVATE_RESPONSE"

    run(executor.execute("send", call(), dispatch, token))
    with sqlite3.connect(executor.audit.path) as db:
        records = [json.loads(row[0]) for row in db.execute("SELECT record FROM events ORDER BY time")]
    assert [row["phase"] for row in records] == ["evaluated", "dispatching", "completed"]
    serialized = json.dumps(records)
    for secret in ("PRIVATE_BODY", "PRIVATE_RESPONSE", "a@example.com", token):
        assert secret not in serialized
    assert records[-1]["actor"] == "operator"


def test_failed_upstream_consumes_approval(executor):
    token = approval(executor)

    async def dispatch(*args):
        raise RuntimeError("upstream failed")

    with pytest.raises(RuntimeError):
        run(executor.execute("send", call(), dispatch, token))
    with pytest.raises(GateDenied):
        run(executor.execute("send", call(), dispatch, token))


def test_binding_rejects_remote_schema_references():
    with pytest.raises(ValidationError):
        Binding.from_dict(
            "read",
            {
                "tool": "document_store",
                "operation": "read",
                "target": "internal://docs",
                "data_classes": ["public"],
                "schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {"x": {"$ref": "https://example.com/schema"}},
                },
            },
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX file mode semantics")
def test_existing_public_state_file_rejected(tmp_path):
    path = tmp_path / "public.db"
    path.touch(mode=0o644)
    path.chmod(0o644)
    with pytest.raises(ValidationError):
        ApprovalStore(path, b"k" * 32)

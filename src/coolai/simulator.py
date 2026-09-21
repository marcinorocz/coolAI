"""Offline policy regression checks; never calls an upstream tool."""

from collections import Counter

from .engine import Decision, Gate, ValidationError, digest, identifier, obj
from .runtime import Binding


def simulate(cases: list, gate: Gate, bindings: dict[str, Binding], compare: Gate | None = None) -> dict:
    if not isinstance(cases, list) or len(cases) > 10000:
        raise ValidationError("Expected up to 10000 scenarios.")
    rows, seen = [], set()
    rank = {Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 1, Decision.BLOCK: 2}
    for case in cases:
        obj(case, {"id", "name", "arguments", "expected"}, {"id", "name", "arguments"})
        if not isinstance(case["id"], str) or not case["id"] or case["id"] in seen:
            raise ValidationError("Scenario IDs must be unique strings.")
        seen.add(case["id"])
        if identifier(case["name"]) not in bindings:
            raise ValidationError("Scenario refers to an unregistered tool.")
        if "expected" in case and case["expected"] not in {d.value for d in Decision}:
            raise ValidationError("Invalid expected decision.")
        action = bindings[case["name"]].action(case["arguments"])
        before = gate.evaluate(action)
        after = compare.evaluate(action) if compare else before
        rows.append(
            {
                "id": case["id"],
                "before": before.decision.value,
                "after": after.decision.value,
                "rule_ids": list(after.rule_ids),
                "changed": before.decision != after.decision,
                "relaxed": rank[after.decision] < rank[before.decision],
                "matches_expected": case.get("expected", after.decision.value) == after.decision.value,
            }
        )
    return {
        "policy_id": gate.fingerprint,
        "candidate_policy_id": compare.fingerprint if compare else gate.fingerprint,
        "bindings_id": digest({n: b.as_dict() for n, b in bindings.items()}),
        "total": len(rows),
        "decisions": dict(Counter(row["after"] for row in rows)),
        "changed": sum(row["changed"] for row in rows),
        "relaxed": sum(row["relaxed"] for row in rows),
        "failed_expectations": sum(not row["matches_expected"] for row in rows),
        "cases": rows,
    }

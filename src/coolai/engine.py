"""Deterministic, fail-closed policy evaluation. No tool execution or network I/O."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit


class ValidationError(ValueError):
    """Invalid action or trusted configuration; never interpreted as permission."""


def canonical(value: Any) -> str:
    def validate(node, depth=0):
        if depth > 32:
            raise ValidationError("JSON nesting exceeds 32 levels.")
        if isinstance(node, dict):
            if not all(isinstance(k, str) for k in node):
                raise ValidationError("JSON keys must be strings.")
            for child in node.values():
                validate(child, depth + 1)
        elif isinstance(node, (list, tuple)):
            for child in node:
                validate(child, depth + 1)
        elif node is not None and type(node) not in (str, int, float, bool):
            raise ValidationError("Expected JSON-compatible data.")

    validate(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValidationError("Expected finite JSON data.") from exc


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def obj(value: Any, allowed: set[str], required: set[str] = frozenset()) -> dict:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise ValidationError("Expected an object with string keys.")
    if set(value) - allowed or required - set(value):
        raise ValidationError("Unknown or missing fields.")
    return value


def identifier(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", value):
        raise ValidationError("Expected a lowercase identifier (maximum 80 characters).")
    return value


def strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > 100:
        raise ValidationError("Expected a list of identifiers.")
    result = tuple(identifier(v) for v in value)
    if len(set(result)) != len(result):
        raise ValidationError("Duplicate identifiers.")
    return result


class Decision(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


DATA_CLASSES = frozenset({"public", "personal", "financial", "health", "credential", "secret"})
READ_OPERATIONS = frozenset({"read", "list", "search"})
WRITE_OPERATIONS = frozenset(
    {"write", "update", "create", "share", "delete", "send", "sign", "publish", "transfer"}
)
OPERATIONS = READ_OPERATIONS | WRITE_OPERATIONS
DEFAULT_TOOLS = (
    ("document_store", ("read", "list", "search")),
    ("filesystem", ("read", "list")),
    ("mailer", ("send",)),
    ("crm", ("read", "create", "update")),
    ("http", ("read", "write")),
)


@dataclass(frozen=True)
class ToolCall:
    tool: str
    operation: str
    target: str = ""
    data_classes: tuple[str, ...] = ()
    prompt: str = ""
    arguments_json: str = "{}"

    def __post_init__(self) -> None:
        identifier(self.tool)
        identifier(self.operation)
        object.__setattr__(self, "data_classes", strings(self.data_classes))
        if set(self.data_classes) - DATA_CLASSES:
            raise ValidationError("Unknown data classification.")
        for value, limit in ((self.target, 2048), (self.prompt, 65536), (self.arguments_json, 131072)):
            if not isinstance(value, str) or len(value) > limit:
                raise ValidationError("Invalid or oversized action field.")
        try:
            args = json.loads(self.arguments_json)
        except (ValueError, RecursionError) as exc:
            raise ValidationError("Invalid arguments JSON.") from exc
        if not isinstance(args, dict):
            raise ValidationError("Arguments must be an object.")
        object.__setattr__(self, "arguments_json", canonical(args))

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ToolCall:
        obj(
            raw, {"tool", "operation", "target", "data_classes", "prompt", "arguments"}, {"tool", "operation"}
        )
        return cls(
            tool=raw["tool"],
            operation=raw["operation"],
            target=raw.get("target", ""),
            data_classes=strings(raw.get("data_classes", [])),
            prompt=raw.get("prompt", ""),
            arguments_json=canonical(raw.get("arguments", {})),
        )

    def as_dict(self) -> dict:
        return {
            "tool": self.tool,
            "operation": self.operation,
            "target": self.target,
            "data_classes": list(self.data_classes),
            "prompt": self.prompt,
            "arguments": json.loads(self.arguments_json),
        }

    @property
    def fingerprint(self) -> str:
        return digest(self.as_dict())


@dataclass(frozen=True)
class Evaluation:
    decision: Decision
    reasons: tuple[str, ...]
    rule_ids: tuple[str, ...]
    action_id: str
    policy_id: str

    def as_dict(self) -> dict:
        # Deliberately excludes prompts, arguments, targets and data.
        return {
            "decision": self.decision.value,
            "reasons": list(self.reasons),
            "rule_ids": list(self.rule_ids),
            "action_id": self.action_id,
            "policy_id": self.policy_id,
        }


def destination(target: str) -> tuple[str, str]:
    """Classify explicit targets; reject ambiguous encodings and unsupported schemes."""
    if not target or any(c.isspace() or ord(c) < 32 for c in target) or "\\" in target:
        raise ValidationError("Missing or ambiguous target.")
    if any(c in target for c in ("%", "#", "?")):
        raise ValidationError("Encoded or fragmented targets are not supported.")
    if target.lower().startswith(("email:", "mailto:")):
        address = target.split(":", 1)[1]
        if not re.fullmatch(r"[A-Za-z0-9.!#$&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+", address):
            raise ValidationError("Expected one plain email recipient.")
        return "external", domain(address.rsplit("@", 1)[1])
    try:
        parsed = urlsplit(target)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValidationError("Credentials, queries and fragments are not supported in targets.")
        if parsed.scheme == "internal" and parsed.netloc and not parsed.port:
            domain(parsed.netloc)
            return "internal", parsed.netloc.lower()
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            if parsed.port not in (None, 80, 443):
                raise ValidationError("Nonstandard target port.")
            return "external", domain(parsed.hostname)
    except ValueError as exc:
        raise ValidationError("Malformed target.") from exc
    raise ValidationError("Unsupported target scheme.")


def domain(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 253:
        raise ValidationError("Invalid domain.")
    value = value.lower()
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split(".")):
        raise ValidationError("Expected an ASCII domain without wildcards or a trailing dot.")
    return value


@dataclass(frozen=True)
class Gate:
    tools: tuple[tuple[str, tuple[str, ...]], ...] = DEFAULT_TOOLS
    trusted_domains: tuple[str, ...] = ()
    external_data_classes: tuple[str, ...] = ()
    approval_operations: tuple[str, ...] = tuple(sorted(WRITE_OPERATIONS))
    version: int = 1
    _injection_patterns: tuple = field(
        default=(
            re.compile(r"ignore\s+(?:(?:all|any)\s+)?(?:previous|above)\s+instructions", re.I),
            re.compile(r"reveal\s+(?:the\s+)?(?:secret|system prompt|credentials)", re.I),
            re.compile(r"bypass\s+(?:the\s+)?(?:policy|approval|guard)", re.I),
            re.compile(r"zignoruj\s+(?:wszystkie\s+)?(?:poprzednie|wcześniejsze)\s+instrukcje", re.I),
        ),
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValidationError("Unsupported policy schema version.")
        if not isinstance(self.tools, (list, tuple)):
            raise ValidationError("Invalid tool registry.")
        entries = []
        for name, operations in self.tools:
            operations = strings(operations)
            if set(operations) - OPERATIONS:
                raise ValidationError("Unknown operation in policy.")
            entries.append((identifier(name), tuple(sorted(operations))))
        if len(dict(entries)) != len(entries):
            raise ValidationError("Duplicate tool.")
        object.__setattr__(self, "tools", tuple(sorted(entries)))
        if not isinstance(self.trusted_domains, (list, tuple)):
            raise ValidationError("trusted_domains must be a list.")
        object.__setattr__(self, "trusted_domains", tuple(sorted({domain(d) for d in self.trusted_domains})))
        for key in ("external_data_classes", "approval_operations"):
            object.__setattr__(self, key, tuple(sorted(strings(getattr(self, key)))))
        if set(self.external_data_classes) - {"personal", "financial", "health"}:
            raise ValidationError("Secrets and credentials cannot be authorized for external transfer.")
        if set(self.approval_operations) - OPERATIONS:
            raise ValidationError("Unknown approval operation.")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Gate:
        obj(
            raw,
            {"version", "tools", "trusted_domains", "external_data_classes", "approval_operations"},
            {"version", "tools"},
        )
        registry = raw["tools"]
        if not isinstance(registry, dict):
            raise ValidationError("tools must map names to operation lists.")
        return cls(
            version=raw["version"],
            tools=tuple(registry.items()),
            trusted_domains=raw.get("trusted_domains", []),
            external_data_classes=raw.get("external_data_classes", []),
            approval_operations=raw.get("approval_operations", tuple(sorted(WRITE_OPERATIONS))),
        )

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "tools": {k: list(v) for k, v in self.tools},
            "trusted_domains": list(self.trusted_domains),
            "external_data_classes": list(self.external_data_classes),
            "approval_operations": list(self.approval_operations),
        }

    @property
    def fingerprint(self) -> str:
        return digest(self.as_dict())

    def evaluate(self, action: ToolCall) -> Evaluation:
        def result(decision: Decision, rule: str, reason: str) -> Evaluation:
            return Evaluation(decision, (reason,), (rule,), action.fingerprint, self.fingerprint)

        if action.operation not in dict(self.tools).get(action.tool, ()):
            return result(Decision.BLOCK, "unknown_operation", "Tool/operation is not explicitly registered.")
        try:
            location, host = destination(action.target)
        except ValidationError:
            return result(Decision.BLOCK, "invalid_target", "Target is missing, ambiguous or unsupported.")
        if any(p.search(action.prompt + "\n" + action.arguments_json) for p in self._injection_patterns):
            return result(
                Decision.BLOCK, "injection_heuristic", "A known suspicious instruction pattern matched."
            )
        sensitive = set(action.data_classes) - {"public"}
        if location == "external" and sensitive:
            if host not in self.trusted_domains or sensitive - set(self.external_data_classes):
                return result(
                    Decision.BLOCK,
                    "external_sensitive_data",
                    "Sensitive transfer is not authorized by policy.",
                )
        # Write operations cannot be downgraded to read-only through configuration.
        if action.operation in WRITE_OPERATIONS or action.operation in self.approval_operations:
            return result(
                Decision.REQUIRE_APPROVAL, "consequential_action", "This operation requires human approval."
            )
        if sensitive:
            return result(
                Decision.REQUIRE_APPROVAL, "sensitive_access", "Access to sensitive data requires approval."
            )
        if location == "external":
            return result(Decision.REQUIRE_APPROVAL, "external_access", "External access requires approval.")
        return result(Decision.ALLOW, "registered_read", "Registered internal read-only action.")

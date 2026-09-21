"""Small, dependency-light policy engine for AI agent actions."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
import re
from typing import Any


class Decision(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


@dataclass(frozen=True)
class ToolCall:
    """A normalized intent emitted before an agent invokes a tool."""

    tool: str
    operation: str
    target: str = ""
    data_classes: tuple[str, ...] = ()
    prompt: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ToolCall":
        return cls(
            tool=raw["tool"],
            operation=raw["operation"],
            target=raw.get("target", ""),
            data_classes=tuple(raw.get("data_classes", ())),
            prompt=raw.get("prompt", ""),
        )


@dataclass(frozen=True)
class Evaluation:
    decision: Decision
    reasons: tuple[str, ...]
    action: ToolCall

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["decision"] = self.decision.value
        return result


@dataclass
class Gate:
    """Evaluate a tool call against a deliberately readable policy."""

    destructive_operations: set[str] = field(
        default_factory=lambda: {"delete", "send", "sign", "publish", "transfer"}
    )
    approval_operations: set[str] = field(
        default_factory=lambda: {"write", "update", "create", "share"}
    )
    sensitive_data: set[str] = field(
        default_factory=lambda: {"personal", "financial", "health", "credential", "secret"}
    )
    external_targets: tuple[str, ...] = ("http://", "https://", "email:")

    _injection_patterns = (
        re.compile(r"ignore (all |any )?(previous|above) instructions", re.I),
        re.compile(r"reveal (the )?(secret|system prompt|credentials)", re.I),
        re.compile(r"bypass (the )?(policy|approval|guard)", re.I),
    )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Gate":
        return cls(
            destructive_operations=set(raw.get("destructive_operations", ())) or cls().destructive_operations,
            approval_operations=set(raw.get("approval_operations", ())) or cls().approval_operations,
            sensitive_data=set(raw.get("sensitive_data", ())) or cls().sensitive_data,
            external_targets=tuple(raw.get("external_targets", ())) or cls().external_targets,
        )

    def evaluate(self, action: ToolCall) -> Evaluation:
        reasons: list[str] = []
        prompt = action.prompt.strip()
        if any(pattern.search(prompt) for pattern in self._injection_patterns):
            return Evaluation(Decision.BLOCK, ("Prompt-injection pattern detected.",), action)

        sensitive = set(action.data_classes) & self.sensitive_data
        is_external = action.target.startswith(self.external_targets)
        if sensitive and is_external:
            return Evaluation(
                Decision.BLOCK,
                (f"Sensitive data ({', '.join(sorted(sensitive))}) cannot be sent to an external target.",),
                action,
            )

        if action.operation in self.destructive_operations:
            reasons.append(f"'{action.operation}' can create an irreversible external effect.")
        if action.operation in self.approval_operations:
            reasons.append(f"'{action.operation}' changes data or permissions.")
        if sensitive:
            reasons.append(f"Sensitive data present: {', '.join(sorted(sensitive))}.")

        if reasons:
            return Evaluation(Decision.REQUIRE_APPROVAL, tuple(reasons), action)
        return Evaluation(Decision.ALLOW, ("Read-only, low-risk action.",), action)

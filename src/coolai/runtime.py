"""Trusted bindings and the only dispatch path to real tools."""

import json
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from types import MappingProxyType

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from jsonschema.exceptions import ValidationError as SchemaValidationError

from .approvals import ApprovalError, ApprovalStore
from .audit import AuditLog
from .engine import (
    Decision,
    Evaluation,
    Gate,
    ToolCall,
    ValidationError,
    canonical,
    digest,
    identifier,
    obj,
    strings,
)


@dataclass(frozen=True)
class Binding:
    name: str
    tool: str
    operation: str
    schema_json: str
    target: str = ""
    target_argument: str = ""
    data_classes: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, name: str, raw: dict) -> "Binding":
        obj(
            raw,
            {"tool", "operation", "schema", "target", "target_argument", "data_classes"},
            {"tool", "operation", "schema", "data_classes"},
        )
        return cls(
            identifier(name),
            identifier(raw["tool"]),
            identifier(raw["operation"]),
            canonical(raw["schema"]),
            raw.get("target", ""),
            raw.get("target_argument", ""),
            strings(raw["data_classes"]),
        )

    def __post_init__(self):
        identifier(self.name)
        identifier(self.tool)
        identifier(self.operation)
        if bool(self.target) == bool(self.target_argument):
            raise ValidationError("Binding needs exactly one fixed target or target_argument.")
        if not isinstance(self.target, str) or not isinstance(self.target_argument, str):
            raise ValidationError("Invalid binding target.")
        # Validate classifications and operation using the same action contract.
        validated = ToolCall(self.tool, self.operation, data_classes=self.data_classes)
        object.__setattr__(self, "data_classes", validated.data_classes)
        try:
            schema = json.loads(self.schema_json)
            Draft202012Validator.check_schema(schema)
        except (ValueError, SchemaError) as exc:
            raise ValidationError("Invalid binding schema.") from exc
        if (
            not isinstance(schema, dict)
            or schema.get("type") != "object"
            or schema.get("additionalProperties") is not False
        ):
            raise ValidationError("Binding schema must be a closed object.")

        # No remote schema retrieval, including implicit network access.
        def inspect(value):
            if isinstance(value, dict):
                if any(k in value for k in ("$ref", "$dynamicRef", "$recursiveRef")):
                    raise ValidationError("Schema references are not supported.")
                for child in value.values():
                    inspect(child)
            elif isinstance(value, list):
                for child in value:
                    inspect(child)

        inspect(schema)
        if self.target_argument:
            if (
                self.target_argument not in schema.get("required", [])
                or schema.get("properties", {}).get(self.target_argument, {}).get("type") != "string"
            ):
                raise ValidationError("Target argument must be a required string.")

    def action(self, arguments: dict) -> ToolCall:
        snapshot = canonical(arguments)
        if len(snapshot) > 131072:
            raise ValidationError("Arguments exceed 128 KiB.")
        arguments = json.loads(snapshot)
        try:
            Draft202012Validator(json.loads(self.schema_json)).validate(arguments)
        except SchemaValidationError as exc:
            raise ValidationError("Arguments do not match the trusted tool schema.") from exc
        return ToolCall(
            self.tool,
            self.operation,
            target=arguments[self.target_argument] if self.target_argument else self.target,
            data_classes=self.data_classes,
            arguments_json=snapshot,
        )

    def as_dict(self):
        return {
            "name": self.name,
            "tool": self.tool,
            "operation": self.operation,
            "schema": json.loads(self.schema_json),
            "target": self.target,
            "target_argument": self.target_argument,
            "data_classes": list(self.data_classes),
        }


def load_bindings(raw: dict) -> dict[str, Binding]:
    if not isinstance(raw, dict) or not raw:
        raise ValidationError("A nonempty binding registry is required.")
    return {name: Binding.from_dict(name, value) for name, value in raw.items()}


class GateDenied(Exception):
    def __init__(self, evaluation: Evaluation):
        self.evaluation = evaluation
        super().__init__(evaluation.decision.value)


class GuardedExecutor:
    def __init__(
        self,
        gate: Gate,
        bindings: dict[str, Binding],
        audit: AuditLog,
        approvals: ApprovalStore | None = None,
        scope: str = "local",
    ):
        self.gate, self.audit, self.approvals = gate, audit, approvals
        self.bindings = MappingProxyType(dict(bindings))
        self.scope = scope

    @property
    def policy_id(self):
        return digest(
            {
                "gate": self.gate.as_dict(),
                "bindings": {k: b.as_dict() for k, b in self.bindings.items()},
                "scope": self.scope,
            }
        )

    def prepare(self, name: str, arguments: dict) -> tuple[ToolCall, Evaluation]:
        identifier(name)
        if name not in self.bindings:
            raise ValidationError("Unregistered tool.")
        action = self.bindings[name].action(arguments)
        # Include upstream name: two tools with identical arguments are distinct approvals.
        result = replace(
            self.gate.evaluate(action),
            action_id=digest({"name": name, "action": action.as_dict()}),
            policy_id=self.policy_id,
        )
        return action, result

    async def execute(
        self,
        name: str,
        arguments: dict,
        dispatch: Callable[[str, dict], Awaitable],
        approval_token: str | None = None,
    ):
        request_id = uuid.uuid4().hex
        try:
            action, result = self.prepare(name, arguments)
        except ValidationError:
            rejected = Evaluation(
                Decision.BLOCK, ("Invalid tool call.",), ("invalid_tool_call",), "unavailable", self.policy_id
            )
            self.audit.record(rejected, "rejected", request_id)
            raise
        self.audit.record(result, "evaluated", request_id)
        if result.decision is Decision.BLOCK:
            raise GateDenied(result)
        actor = None
        if result.decision is Decision.REQUIRE_APPROVAL:
            if self.approvals is None or approval_token is None:
                raise GateDenied(result)
            try:
                actor = self.approvals.consume(approval_token, result.action_id, result.policy_id)
            except ApprovalError:
                self.audit.record(result, "approval_rejected", request_id)
                raise GateDenied(result) from None
        # Persistence failures before this point cannot result in a tool call.
        self.audit.record(result, "dispatching", request_id, actor)
        try:
            output = await dispatch(name, json.loads(action.arguments_json))
        except Exception:
            self.audit.record(result, "upstream_error", request_id, actor)
            raise
        self.audit.record(result, "completed", request_id, actor)
        return output

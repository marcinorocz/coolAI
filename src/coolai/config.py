"""Bounded, duplicate-free configuration and action loading."""

import json
from pathlib import Path

import yaml

from .engine import Gate, ValidationError


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise ValidationError("Duplicate or non-string key.")
        result[key] = value
    return result


class StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ValidationError("YAML aliases are not supported.")
        return super().compose_node(parent, index)


def mapping(loader, node):
    return unique_pairs(
        (loader.construct_object(k), loader.construct_object(v, deep=True)) for k, v in node.value
    )


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def load(path: Path):
    try:
        with path.open("rb") as handle:
            data = handle.read(1_048_577)
        if len(data) > 1_048_576:
            raise ValidationError("Input exceeds 1 MiB.")
        text = data.decode("utf-8")
        if path.suffix.lower() == ".json":
            return json.loads(
                text,
                object_pairs_hook=unique_pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(ValidationError("Non-finite number.")),
            )
        return yaml.load(text, Loader=StrictLoader)
    except (OSError, UnicodeError, ValueError, yaml.YAMLError, RecursionError) as exc:
        raise ValidationError("Cannot load valid JSON/YAML input.") from exc


def load_policy(path: Path | None) -> Gate:
    return Gate() if path is None else Gate.from_dict(load(path))

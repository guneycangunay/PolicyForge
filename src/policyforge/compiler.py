from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any, TypeGuard

from .conditions import validate_condition
from .models import Condition, Effect, JsonValue, PolicyBundle, Rule

MAX_RULES = 256
MAX_PATTERNS_PER_RULE = 64
_IDENTIFIER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}\*?$")


class PolicyValidationError(ValueError):
    pass


def compile_policy(document: Mapping[str, Any]) -> PolicyBundle:
    tenant_id = _required_identifier(document, "tenant_id")
    version = document.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise PolicyValidationError("version must be a positive integer")
    raw_rules = document.get("rules")
    if not _is_sequence(raw_rules) or not 1 <= len(raw_rules) <= MAX_RULES:
        raise PolicyValidationError(f"rules must contain between 1 and {MAX_RULES} entries")

    rules: list[Rule] = []
    seen: set[str] = set()
    for raw_rule in raw_rules:
        if not isinstance(raw_rule, Mapping):
            raise PolicyValidationError("each rule must be an object")
        rule = _compile_rule(raw_rule)
        if rule.rule_id in seen:
            raise PolicyValidationError(f"duplicate rule id: {rule.rule_id}")
        seen.add(rule.rule_id)
        rules.append(rule)
    return PolicyBundle(tenant_id=tenant_id, version=version, rules=tuple(rules))


def _compile_rule(document: Mapping[str, Any]) -> Rule:
    rule_id = _required_identifier(document, "id")
    try:
        effect = Effect(document.get("effect"))
    except ValueError as error:
        raise PolicyValidationError(f"rule {rule_id} effect must be allow or deny") from error
    actions = _patterns(document.get("actions"), rule_id, "actions")
    resources = _patterns(document.get("resources"), rule_id, "resources")
    roles_any = frozenset(_identifiers(document.get("roles_any", []), rule_id, "roles_any"))

    raw_condition = document.get("condition")
    condition: Condition | None = None
    if raw_condition is not None:
        if not isinstance(raw_condition, Mapping):
            raise PolicyValidationError(f"rule {rule_id} condition must be an object")
        try:
            validate_condition(raw_condition)
        except ValueError as error:
            raise PolicyValidationError(f"rule {rule_id}: {error}") from error
        condition = _freeze_json(raw_condition)  # type: ignore[assignment]

    raw_obligations = document.get("obligations", {})
    if not isinstance(raw_obligations, Mapping) or len(raw_obligations) > 32:
        raise PolicyValidationError(
            f"rule {rule_id} obligations must be an object of at most 32 keys"
        )
    obligations = _freeze_json(raw_obligations)
    assert isinstance(obligations, Mapping)
    return Rule(
        rule_id=rule_id,
        effect=effect,
        actions=actions,
        resources=resources,
        roles_any=roles_any,
        condition=condition,
        obligations=obligations,
    )


def _patterns(value: Any, rule_id: str, field: str) -> tuple[str, ...]:
    if not _is_sequence(value) or not 1 <= len(value) <= MAX_PATTERNS_PER_RULE:
        raise PolicyValidationError(
            f"rule {rule_id} {field} must contain between 1 and {MAX_PATTERNS_PER_RULE} patterns"
        )
    result: list[str] = []
    for pattern in value:
        if not isinstance(pattern, str) or not _PATTERN.fullmatch(pattern) or "**" in pattern:
            raise PolicyValidationError(f"rule {rule_id} contains invalid {field} pattern")
        result.append(pattern)
    return tuple(result)


def _identifiers(value: Any, rule_id: str, field: str) -> tuple[str, ...]:
    if not _is_sequence(value) or len(value) > MAX_PATTERNS_PER_RULE:
        raise PolicyValidationError(f"rule {rule_id} {field} must be a bounded array")
    result: list[str] = []
    for identifier in value:
        if not isinstance(identifier, str) or not _IDENTIFIER.fullmatch(identifier):
            raise PolicyValidationError(f"rule {rule_id} contains invalid {field} identifier")
        result.append(identifier)
    return tuple(result)


def _required_identifier(document: Mapping[str, Any], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise PolicyValidationError(f"{field} must be a safe identifier of at most 64 characters")
    return value


def _freeze_json(value: Any) -> JsonValue:
    if value is None or isinstance(value, bool | str):
        return value
    if isinstance(value, int | float) and not isinstance(value, bool):
        if isinstance(value, float) and (value != value or abs(value) == float("inf")):
            raise PolicyValidationError("policy numbers must be finite")
        return value
    if _is_sequence(value):
        return [_freeze_json(item) for item in value]
    if isinstance(value, Mapping):
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise PolicyValidationError("policy object keys must be strings")
            result[key] = _freeze_json(item)
        return MappingProxyType(result)
    raise PolicyValidationError("policy contains a non-JSON value")


def _is_sequence(value: object) -> TypeGuard[Sequence[Any]]:
    return isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray)

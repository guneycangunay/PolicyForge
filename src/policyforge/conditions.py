from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, TypeGuard

from .models import AuthorizationRequest, Condition, JsonValue

MAX_CONDITION_DEPTH = 12
MAX_CONDITION_NODES = 128
_PATH = re.compile(r"^(principal|resource|environment)(\.[a-zA-Z][a-zA-Z0-9_-]{0,63}){1,8}$")
_BOOLEAN_OPERATORS = frozenset({"all", "any", "not"})
_BINARY_OPERATORS = frozenset({"eq", "ne", "lt", "lte", "gt", "gte", "in", "contains"})


class ConditionError(ValueError):
    pass


def validate_condition(condition: Condition) -> None:
    counter = [0]
    _validate_condition(condition, depth=1, counter=counter)


def evaluate_condition(condition: Condition, request: AuthorizationRequest) -> bool:
    context: Mapping[str, Any] = {
        "principal": {
            "id": request.principal.principal_id,
            "tenant_id": request.principal.tenant_id,
            "roles": sorted(request.principal.roles),
            "attributes": request.principal.attributes,
        },
        "resource": {
            "id": request.resource.resource_id,
            "type": request.resource.resource_type,
            "tenant_id": request.resource.tenant_id,
            "attributes": request.resource.attributes,
        },
        "environment": request.environment,
    }
    return _evaluate(condition, context)


def _validate_condition(condition: Condition, depth: int, counter: list[int]) -> None:
    counter[0] += 1
    if counter[0] > MAX_CONDITION_NODES:
        raise ConditionError(f"condition exceeds {MAX_CONDITION_NODES} nodes")
    if depth > MAX_CONDITION_DEPTH:
        raise ConditionError(f"condition exceeds depth {MAX_CONDITION_DEPTH}")
    if len(condition) != 1:
        raise ConditionError("each condition must contain exactly one operator")

    operator, argument = next(iter(condition.items()))
    if operator in {"all", "any"}:
        if not _is_sequence(argument) or not argument:
            raise ConditionError(f"{operator} requires a non-empty condition array")
        for child in argument:
            if not isinstance(child, Mapping):
                raise ConditionError(f"{operator} children must be condition objects")
            _validate_condition(child, depth + 1, counter)
        return
    if operator == "not":
        if not isinstance(argument, Mapping):
            raise ConditionError("not requires one condition object")
        _validate_condition(argument, depth + 1, counter)
        return
    if operator == "present":
        _validate_operand(argument, allow_literal=False)
        return
    if operator in _BINARY_OPERATORS:
        if not _is_sequence(argument) or len(argument) != 2:
            raise ConditionError(f"{operator} requires exactly two operands")
        _validate_operand(argument[0])
        _validate_operand(argument[1])
        return
    raise ConditionError(f"unsupported condition operator: {operator}")


def _validate_operand(value: JsonValue, *, allow_literal: bool = True) -> None:
    if not isinstance(value, Mapping) or len(value) != 1:
        raise ConditionError("operand must contain exactly one of path or value")
    if "path" in value:
        path = value["path"]
        if not isinstance(path, str) or not _PATH.fullmatch(path):
            raise ConditionError(f"invalid attribute path: {path}")
        return
    if allow_literal and "value" in value:
        return
    raise ConditionError("operand must contain path or value")


def _evaluate(condition: Condition, context: Mapping[str, Any]) -> bool:
    operator, argument = next(iter(condition.items()))
    if operator == "all":
        return all(_evaluate(child, context) for child in argument)  # type: ignore[arg-type]
    if operator == "any":
        return any(_evaluate(child, context) for child in argument)  # type: ignore[arg-type]
    if operator == "not":
        return not _evaluate(argument, context)  # type: ignore[arg-type]
    if operator == "present":
        present, _ = _resolve_operand(argument, context)
        return present

    left_present, left = _resolve_operand(argument[0], context)  # type: ignore[index]
    right_present, right = _resolve_operand(argument[1], context)  # type: ignore[index]
    if not left_present or not right_present:
        return False
    if operator == "eq":
        return left == right
    if operator == "ne":
        return left != right
    if operator == "in":
        return isinstance(right, (list, tuple, frozenset)) and left in right
    if operator == "contains":
        return isinstance(left, (str, list, tuple, frozenset)) and right in left
    try:
        if operator == "lt":
            return left < right
        if operator == "lte":
            return left <= right
        if operator == "gt":
            return left > right
        if operator == "gte":
            return left >= right
    except TypeError:
        return False
    return False


def _resolve_operand(operand: JsonValue, context: Mapping[str, Any]) -> tuple[bool, Any]:
    assert isinstance(operand, Mapping)
    if "value" in operand:
        return True, operand["value"]
    path = operand["path"]
    assert isinstance(path, str)
    current: Any = context
    for segment in path.split("."):
        if not isinstance(current, Mapping) or segment not in current:
            return False, None
        current = current[segment]
    return True, current


def _is_sequence(value: object) -> TypeGuard[Sequence[JsonValue]]:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping, Protocol, TypeAlias

JsonScalar: TypeAlias = None | bool | int | float | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | Mapping[str, "JsonValue"]
Condition: TypeAlias = Mapping[str, JsonValue]


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    effect: Effect
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    roles_any: frozenset[str] = frozenset()
    condition: Condition | None = None
    obligations: Mapping[str, JsonValue] = field(
        default_factory=lambda: MappingProxyType({})
    )


@dataclass(frozen=True, slots=True)
class PolicyBundle:
    tenant_id: str
    version: int
    rules: tuple[Rule, ...]


@dataclass(frozen=True, slots=True)
class Principal:
    principal_id: str
    tenant_id: str
    roles: frozenset[str]
    attributes: Mapping[str, JsonValue] = field(default_factory=lambda: MappingProxyType({}))


@dataclass(frozen=True, slots=True)
class Resource:
    resource_type: str
    resource_id: str
    tenant_id: str
    attributes: Mapping[str, JsonValue] = field(default_factory=lambda: MappingProxyType({}))


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    request_id: str
    action: str
    principal: Principal
    resource: Resource
    environment: Mapping[str, JsonValue] = field(default_factory=lambda: MappingProxyType({}))


@dataclass(frozen=True, slots=True)
class Decision:
    request_id: str
    allowed: bool
    reason: str
    policy_version: int | None
    matched_rule_ids: tuple[str, ...] = ()
    obligations: Mapping[str, JsonValue] = field(default_factory=lambda: MappingProxyType({}))
    cache_hit: bool = False


class DecisionSink(Protocol):
    def record(self, request: AuthorizationRequest, decision: Decision) -> None: ...

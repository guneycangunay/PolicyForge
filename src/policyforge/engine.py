from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from threading import RLock
from types import MappingProxyType
from typing import Any

from .cache import DecisionCache
from .conditions import evaluate_condition
from .models import (
    AuthorizationRequest,
    Decision,
    DecisionSink,
    Effect,
    JsonValue,
    PolicyBundle,
    Rule,
)


class PolicyVersionError(ValueError):
    pass


class AuthorizationEngine:
    def __init__(
        self,
        *,
        cache: DecisionCache | None = None,
        decision_sink: DecisionSink | None = None,
    ) -> None:
        self._policies: dict[str, PolicyBundle] = {}
        self._cache = cache or DecisionCache()
        self._decision_sink = decision_sink
        self._lock = RLock()

    def publish(self, policy: PolicyBundle) -> None:
        with self._lock:
            current = self._policies.get(policy.tenant_id)
            if current is not None and policy.version <= current.version:
                raise PolicyVersionError(
                    f"policy version must increase beyond {current.version} for {policy.tenant_id}"
                )
            self._policies[policy.tenant_id] = policy
            self._cache.invalidate_tenant(policy.tenant_id)

    def authorize(self, request: AuthorizationRequest) -> Decision:
        if (
            request.principal.tenant_id != request.resource.tenant_id
            or request.principal.tenant_id == ""
        ):
            return self._record(request, self._deny(request, "cross_tenant", None))

        tenant_id = request.principal.tenant_id
        with self._lock:
            policy = self._policies.get(tenant_id)
        if policy is None:
            return self._record(request, self._deny(request, "no_policy", None))

        cache_key = _request_cache_key(request, policy.version)
        cached = self._cache.get(tenant_id, cache_key)
        if cached is not None:
            return self._record(
                request,
                replace(cached, request_id=request.request_id, cache_hit=True),
            )

        matching = tuple(rule for rule in policy.rules if _matches(rule, request))
        denied = tuple(sorted(rule.rule_id for rule in matching if rule.effect is Effect.DENY))
        if denied:
            decision = self._deny(request, "explicit_deny", policy.version, denied)
        else:
            allowed_rules = tuple(
                sorted((rule for rule in matching if rule.effect is Effect.ALLOW), key=lambda r: r.rule_id)
            )
            if not allowed_rules:
                decision = self._deny(request, "default_deny", policy.version)
            else:
                obligations = _merge_obligations(allowed_rules)
                if obligations is None:
                    decision = self._deny(
                        request,
                        "conflicting_obligations",
                        policy.version,
                        tuple(rule.rule_id for rule in allowed_rules),
                    )
                else:
                    decision = Decision(
                        request_id=request.request_id,
                        allowed=True,
                        reason="allowed",
                        policy_version=policy.version,
                        matched_rule_ids=tuple(rule.rule_id for rule in allowed_rules),
                        obligations=MappingProxyType(obligations),
                    )
        self._cache.put(tenant_id, cache_key, decision)
        return self._record(request, decision)

    def _deny(
        self,
        request: AuthorizationRequest,
        reason: str,
        policy_version: int | None,
        matched: tuple[str, ...] = (),
    ) -> Decision:
        return Decision(
            request_id=request.request_id,
            allowed=False,
            reason=reason,
            policy_version=policy_version,
            matched_rule_ids=matched,
        )

    def _record(self, request: AuthorizationRequest, decision: Decision) -> Decision:
        if self._decision_sink is not None:
            self._decision_sink.record(request, decision)
        return decision


def _matches(rule: Rule, request: AuthorizationRequest) -> bool:
    if rule.roles_any and not rule.roles_any.intersection(request.principal.roles):
        return False
    if not any(_pattern_matches(pattern, request.action) for pattern in rule.actions):
        return False
    resource = f"{request.resource.resource_type}:{request.resource.resource_id}"
    if not any(_pattern_matches(pattern, resource) for pattern in rule.resources):
        return False
    return rule.condition is None or evaluate_condition(rule.condition, request)


def _pattern_matches(pattern: str, value: str) -> bool:
    return value.startswith(pattern[:-1]) if pattern.endswith("*") else value == pattern


def _merge_obligations(rules: tuple[Rule, ...]) -> dict[str, JsonValue] | None:
    result: dict[str, JsonValue] = {}
    for rule in rules:
        for key, value in rule.obligations.items():
            if key in result and result[key] != value:
                return None
            result[key] = value
    return result


def _request_cache_key(request: AuthorizationRequest, policy_version: int) -> str:
    payload: dict[str, Any] = {
        "policy_version": policy_version,
        "action": request.action,
        "principal": {
            "id": request.principal.principal_id,
            "tenant_id": request.principal.tenant_id,
            "roles": sorted(request.principal.roles),
            "attributes": request.principal.attributes,
        },
        "resource": {
            "type": request.resource.resource_type,
            "id": request.resource.resource_id,
            "tenant_id": request.resource.tenant_id,
            "attributes": request.resource.attributes,
        },
        "environment": request.environment,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()

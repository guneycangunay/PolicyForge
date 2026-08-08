from __future__ import annotations

import unittest
from dataclasses import replace

from policyforge import (
    AuthorizationEngine,
    AuthorizationRequest,
    DecisionCache,
    PolicyVersionError,
    Principal,
    Resource,
    compile_policy,
)


def policy(version: int = 1, *, conflicting_obligations: bool = False):
    rules: list[dict[str, object]] = [
        {
            "id": "deny-high-risk",
            "effect": "deny",
            "actions": ["payment.refund"],
            "resources": ["payment:*"],
            "condition": {
                "gte": [
                    {"path": "environment.risk_score"},
                    {"value": 80},
                ]
            },
        },
        {
            "id": "allow-ops-refund",
            "effect": "allow",
            "actions": ["payment.refund"],
            "resources": ["payment:*"],
            "roles_any": ["payments-ops"],
            "condition": {
                "all": [
                    {
                        "lte": [
                            {"path": "resource.attributes.amount"},
                            {"value": 500},
                        ]
                    },
                    {
                        "eq": [
                            {"path": "principal.attributes.mfa"},
                            {"value": True},
                        ]
                    },
                ]
            },
            "obligations": {"audit_level": "high", "require_mfa": True},
        },
    ]
    if conflicting_obligations:
        rules.append(
            {
                "id": "allow-conflicting-audit",
                "effect": "allow",
                "actions": ["payment.refund"],
                "resources": ["payment:*"],
                "roles_any": ["payments-ops"],
                "obligations": {"audit_level": "low"},
            }
        )
    return compile_policy({"tenant_id": "acme", "version": version, "rules": rules})


def request(
    *,
    request_id: str = "req-1",
    principal_tenant: str = "acme",
    resource_tenant: str = "acme",
    risk_score: int = 20,
    amount: int = 80,
    mfa: bool = True,
    action: str = "payment.refund",
) -> AuthorizationRequest:
    return AuthorizationRequest(
        request_id=request_id,
        action=action,
        principal=Principal(
            principal_id="operator-17",
            tenant_id=principal_tenant,
            roles=frozenset({"payments-ops"}),
            attributes={"mfa": mfa},
        ),
        resource=Resource(
            resource_type="payment",
            resource_id="pay-1042",
            tenant_id=resource_tenant,
            attributes={"amount": amount},
        ),
        environment={"risk_score": risk_score},
    )


class AuthorizationEngineTests(unittest.TestCase):
    def test_allows_matching_role_attributes_and_obligations(self) -> None:
        engine = AuthorizationEngine()
        engine.publish(policy())

        decision = engine.authorize(request())

        self.assertTrue(decision.allowed)
        self.assertEqual("allowed", decision.reason)
        self.assertEqual(("allow-ops-refund",), decision.matched_rule_ids)
        self.assertEqual("high", decision.obligations["audit_level"])

    def test_explicit_deny_overrides_matching_allow(self) -> None:
        engine = AuthorizationEngine()
        engine.publish(policy())

        decision = engine.authorize(request(risk_score=95))

        self.assertFalse(decision.allowed)
        self.assertEqual("explicit_deny", decision.reason)
        self.assertEqual(("deny-high-risk",), decision.matched_rule_ids)

    def test_cross_tenant_access_is_rejected_before_policy(self) -> None:
        engine = AuthorizationEngine()
        engine.publish(policy())

        decision = engine.authorize(request(resource_tenant="other"))

        self.assertFalse(decision.allowed)
        self.assertEqual("cross_tenant", decision.reason)
        self.assertIsNone(decision.policy_version)

    def test_unmatched_action_defaults_to_deny(self) -> None:
        engine = AuthorizationEngine()
        engine.publish(policy())

        decision = engine.authorize(request(action="payment.delete"))

        self.assertFalse(decision.allowed)
        self.assertEqual("default_deny", decision.reason)

    def test_missing_attribute_fails_condition_closed(self) -> None:
        engine = AuthorizationEngine()
        engine.publish(policy())
        source = request()
        without_mfa = replace(
            source,
            principal=replace(source.principal, attributes={}),
        )

        decision = engine.authorize(without_mfa)

        self.assertFalse(decision.allowed)
        self.assertEqual("default_deny", decision.reason)

    def test_cache_expires_and_policy_publish_invalidates_tenant(self) -> None:
        monotonic = [100.0]
        cache = DecisionCache(
            maximum_entries=10,
            ttl_seconds=2.0,
            monotonic=lambda: monotonic[0],
        )
        engine = AuthorizationEngine(cache=cache)
        engine.publish(policy(1))

        self.assertFalse(engine.authorize(request(request_id="first")).cache_hit)
        cached = engine.authorize(request(request_id="second"))
        self.assertTrue(cached.cache_hit)
        self.assertEqual("second", cached.request_id)

        monotonic[0] += 3.0
        self.assertFalse(engine.authorize(request(request_id="third")).cache_hit)
        engine.publish(policy(2))
        refreshed = engine.authorize(request(request_id="fourth"))
        self.assertFalse(refreshed.cache_hit)
        self.assertEqual(2, refreshed.policy_version)

    def test_conflicting_obligations_fail_closed(self) -> None:
        engine = AuthorizationEngine()
        engine.publish(policy(conflicting_obligations=True))

        decision = engine.authorize(request())

        self.assertFalse(decision.allowed)
        self.assertEqual("conflicting_obligations", decision.reason)

    def test_policy_versions_must_increase(self) -> None:
        engine = AuthorizationEngine()
        engine.publish(policy(2))
        with self.assertRaises(PolicyVersionError):
            engine.publish(policy(2))

    def test_missing_tenant_policy_denies(self) -> None:
        decision = AuthorizationEngine().authorize(request())
        self.assertFalse(decision.allowed)
        self.assertEqual("no_policy", decision.reason)


if __name__ == "__main__":
    unittest.main()

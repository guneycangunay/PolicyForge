from __future__ import annotations

import unittest

from policyforge.compiler import PolicyValidationError, compile_policy
from policyforge.conditions import ConditionError, validate_condition


class CompilerTests(unittest.TestCase):
    def test_rejects_duplicate_rule_ids(self) -> None:
        rule = {
            "id": "same",
            "effect": "allow",
            "actions": ["payment.read"],
            "resources": ["payment:*"],
        }
        with self.assertRaisesRegex(PolicyValidationError, "duplicate rule"):
            compile_policy({"tenant_id": "acme", "version": 1, "rules": [rule, rule]})

    def test_rejects_executable_or_unknown_condition_operator(self) -> None:
        with self.assertRaisesRegex(ConditionError, "unsupported"):
            validate_condition({"eval": "principal.is_admin"})

    def test_bounds_condition_depth(self) -> None:
        condition: dict[str, object] = {
            "eq": [{"value": True}, {"value": True}]
        }
        for _ in range(13):
            condition = {"not": condition}
        with self.assertRaisesRegex(ConditionError, "depth"):
            validate_condition(condition)

    def test_rejects_non_terminal_wildcards(self) -> None:
        with self.assertRaisesRegex(PolicyValidationError, "invalid actions pattern"):
            compile_policy(
                {
                    "tenant_id": "acme",
                    "version": 1,
                    "rules": [
                        {
                            "id": "bad-pattern",
                            "effect": "allow",
                            "actions": ["payment.*.force"],
                            "resources": ["payment:*"],
                        }
                    ],
                }
            )


if __name__ == "__main__":
    unittest.main()

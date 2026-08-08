from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from policyforge.audit import AuditIntegrityError, AuditLedger
from policyforge.models import AuthorizationRequest, Decision, Principal, Resource


def request(index: int) -> AuthorizationRequest:
    return AuthorizationRequest(
        request_id=f"request-{index}",
        action="payment.refund",
        principal=Principal("operator", "acme", frozenset({"payments-ops"})),
        resource=Resource("payment", f"payment-{index}", "acme"),
    )


def decision(index: int) -> Decision:
    return Decision(
        request_id=f"request-{index}",
        allowed=True,
        reason="allowed",
        policy_version=1,
        matched_rule_ids=("allow-refund",),
    )


class AuditLedgerTests(unittest.TestCase):
    def test_verifies_concurrent_appends_as_one_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = AuditLedger(Path(directory) / "audit.jsonl", b"k" * 32)
            with ThreadPoolExecutor(max_workers=4) as executor:
                list(executor.map(lambda index: ledger.record(request(index), decision(index)), range(20)))

            self.assertEqual(20, ledger.verify())

    def test_detects_modified_historical_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            ledger = AuditLedger(path, b"k" * 32)
            ledger.record(request(1), decision(1))
            entry = json.loads(path.read_text())
            entry["allowed"] = False
            path.write_text(json.dumps(entry) + "\n")

            with self.assertRaisesRegex(AuditIntegrityError, "HMAC mismatch"):
                ledger.verify()

    def test_rejects_short_hmac_key(self) -> None:
        with self.assertRaises(ValueError):
            AuditLedger("audit.jsonl", b"short")


if __name__ == "__main__":
    unittest.main()

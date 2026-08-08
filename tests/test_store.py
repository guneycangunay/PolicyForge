from __future__ import annotations

import tempfile
import unittest

from policyforge.store import PolicyFileStore


class PolicyFileStoreTests(unittest.TestCase):
    def test_atomically_round_trips_policy_documents(self) -> None:
        document = {
            "tenant_id": "acme",
            "version": 1,
            "rules": [
                {
                    "id": "allow-read",
                    "effect": "allow",
                    "actions": ["payment.read"],
                    "resources": ["payment:*"],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            store = PolicyFileStore(directory)
            store.save("acme", document)
            self.assertEqual([document], store.load_all())

    def test_rejects_unsafe_tenant_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                PolicyFileStore(directory).save("../escape", {})


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "verify_restored_probe_token",
    ROOT / "scripts" / "verify_restored_probe_token.py",
)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)

EXPECTED_POLICY = "restore-probe-read"


def lookup(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "policies": [EXPECTED_POLICY],
        "identity_policies": [],
        "external_namespace_policies": {},
        "renewable": False,
        "ttl": 300,
    }
    data.update(overrides)
    return {"data": data}


class RestoredProbeTokenPolicyTests(unittest.TestCase):
    def assert_rejected(self, document: object) -> None:
        with self.assertRaises(VERIFIER.ProbeTokenValidationError):
            VERIFIER.validate_probe_token(document, EXPECTED_POLICY)

    def test_exact_direct_policy_without_inheritance_passes(self) -> None:
        VERIFIER.validate_probe_token(lookup(), EXPECTED_POLICY)

    def test_matching_token_policies_field_passes_when_present(self) -> None:
        VERIFIER.validate_probe_token(
            lookup(token_policies=[EXPECTED_POLICY]), EXPECTED_POLICY
        )

    def test_reserved_default_and_root_policy_names_are_rejected(self) -> None:
        for policy in ("default", "root", "DeFaUlT", "ROOT"):
            with self.subTest(policy=policy):
                document = lookup(policies=[policy], token_policies=[policy])
                with self.assertRaises(VERIFIER.ProbeTokenValidationError):
                    VERIFIER.validate_probe_token(document, policy)

    def test_additional_direct_policy_is_rejected(self) -> None:
        self.assert_rejected(lookup(policies=[EXPECTED_POLICY, "operator"]))

    def test_additional_token_policy_is_rejected(self) -> None:
        self.assert_rejected(
            lookup(token_policies=[EXPECTED_POLICY, "operator"])
        )

    def test_inherited_identity_policy_is_rejected(self) -> None:
        self.assert_rejected(lookup(identity_policies=["operator"]))

    def test_external_namespace_policy_is_rejected(self) -> None:
        self.assert_rejected(
            lookup(external_namespace_policies={"root/": ["operator"]})
        )

    def test_even_empty_external_namespace_entry_is_rejected(self) -> None:
        self.assert_rejected(lookup(external_namespace_policies={"root/": []}))

    def test_renewable_token_is_rejected(self) -> None:
        self.assert_rejected(lookup(renewable=True))

    def test_missing_or_nonpositive_ttl_is_rejected(self) -> None:
        self.assert_rejected(lookup(ttl=0))
        self.assert_rejected(lookup(ttl=None))

    def test_malformed_effective_policy_collections_fail_closed(self) -> None:
        self.assert_rejected(lookup(identity_policies="operator"))
        self.assert_rejected(lookup(external_namespace_policies=[]))


if __name__ == "__main__":
    unittest.main()

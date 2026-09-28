"""Least-privilege boundary regressions over the committed policy files.

The committed HCL under openbao/policies/ is deployment authority, so these
checks read it directly rather than the generator output.
"""

from __future__ import annotations

import itertools
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "openbao/policies"
ENVIRONMENTS = ("development", "test", "staging", "production")
PATH_BLOCK = re.compile(r'path "([^"]+)" \{\s*capabilities = \[([^\]]*)\]\s*\}')
KV_PATH = re.compile(r"codestra/(data|metadata)/([a-z]+)/([a-z0-9-]+(?:/[a-z0-9-]+)*/)\*")
TOKEN_SELF = {
    "auth/token/lookup-self": {"read"},
    "auth/token/renew-self": {"update"},
    "auth/token/revoke-self": {"update"},
}

# Adapter identities read an exact provider subtree that Middleware Worker
# also reads as the provider-family executor (docs/security/OPENBAO-POLICY-MATRIX.md).
# Any other shared or nested grant between identities is a least-privilege regression.
DECLARED_NESTED_GRANTS = {
    ("middleware-worker", "crawler-adapter"): "middleware/worker/crawler/kyqra/",
    ("middleware-worker", "klyrow-email-adapter"): "middleware/worker/email/klyrow/",
    ("middleware-worker", "telnexa-sms-adapter"): "middleware/worker/sms/telnexa/",
    ("middleware-worker", "vicidial-adapter"): "middleware/worker/telephony/vicidial/",
}


def load_grants() -> dict[tuple[str, str], list[tuple[str, set[str]]]]:
    grants: dict[tuple[str, str], list[tuple[str, set[str]]]] = {}
    for policy in sorted(POLICIES.glob("*/*.hcl")):
        source = policy.read_text(encoding="utf-8")
        blocks = [
            (path, set(re.findall(r'"(\w+)"', capabilities)))
            for path, capabilities in PATH_BLOCK.findall(source)
        ]
        grants[(policy.parent.name, policy.stem)] = [
            (path, capabilities) for path, capabilities in blocks if capabilities != {"deny"}
        ]
    return grants


def kv_data_prefixes(grants: list[tuple[str, set[str]]]) -> list[str]:
    prefixes = []
    for path, _ in grants:
        match = KV_PATH.fullmatch(path)
        if match and match.group(1) == "data":
            prefixes.append(match.group(3))
    return prefixes


class PolicyBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.grants = load_grants()

    def test_policies_exist_for_every_environment(self) -> None:
        environments = {environment for environment, _ in self.grants}
        self.assertEqual(environments, set(ENVIRONMENTS))

    def test_allow_grants_are_read_only_and_environment_scoped(self) -> None:
        for (environment, identity), grants in self.grants.items():
            for path, capabilities in grants:
                with self.subTest(environment=environment, identity=identity, path=path):
                    if path in TOKEN_SELF:
                        self.assertEqual(capabilities, TOKEN_SELF[path])
                        continue
                    if path == "sys/metrics":
                        self.assertEqual(identity, "prometheus-openbao")
                        self.assertEqual(capabilities, {"read"})
                        continue
                    match = KV_PATH.fullmatch(path)
                    self.assertIsNotNone(match, "allow grant outside exact KV v2 service prefix")
                    kind, path_environment, _ = match.groups()
                    self.assertEqual(path_environment, environment)
                    allowed = {"read"} if kind == "data" else {"read", "list"}
                    self.assertLessEqual(capabilities, allowed)

    def test_every_data_grant_has_matching_metadata_grant(self) -> None:
        for (environment, identity), grants in self.grants.items():
            paths = {path for path, _ in grants}
            for prefix in kv_data_prefixes(grants):
                with self.subTest(environment=environment, identity=identity, prefix=prefix):
                    self.assertIn(f"codestra/metadata/{environment}/{prefix}*", paths)

    def test_no_undeclared_shared_or_nested_grants_between_identities(self) -> None:
        for environment in ENVIRONMENTS:
            identities = sorted(
                (identity, kv_data_prefixes(grants))
                for (policy_environment, identity), grants in self.grants.items()
                if policy_environment == environment
            )
            for (first, first_prefixes), (second, second_prefixes) in itertools.combinations(identities, 2):
                for a, b in itertools.product(first_prefixes, second_prefixes):
                    if not (a.startswith(b) or b.startswith(a)):
                        continue
                    with self.subTest(environment=environment, first=first, second=second):
                        pair = tuple(sorted((first, second), key=lambda name: name != "middleware-worker"))
                        self.assertEqual(DECLARED_NESTED_GRANTS.get(pair), max(a, b, key=len))

    def test_kong_and_middleware_cannot_read_each_other(self) -> None:
        for environment in ENVIRONMENTS:
            kong = kv_data_prefixes(self.grants[(environment, "kong-gateway")])
            self.assertEqual(kong, ["kong/"])
            for identity in ("middleware-api", "middleware-worker"):
                prefixes = kv_data_prefixes(self.grants[(environment, identity)])
                with self.subTest(environment=environment, identity=identity):
                    self.assertTrue(prefixes)
                    self.assertTrue(all(prefix.startswith("middleware/") for prefix in prefixes))
                    self.assertNotIn("middleware/", prefixes)
            api = kv_data_prefixes(self.grants[(environment, "middleware-api")])
            worker = kv_data_prefixes(self.grants[(environment, "middleware-worker")])
            self.assertEqual(api, ["middleware/api/"])
            self.assertTrue(all(prefix.startswith("middleware/worker/") for prefix in worker))


if __name__ == "__main__":
    unittest.main(verbosity=2)

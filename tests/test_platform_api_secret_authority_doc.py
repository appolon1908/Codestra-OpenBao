#!/usr/bin/env python3
"""Keep the platform secret authority document aligned with generated source."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PlatformApiSecretAuthorityDocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = (
            ROOT / "docs/PLATFORM-API-SECRETS-V2.md"
        ).read_text(encoding="utf-8")
        cls.authority = json.loads(
            (ROOT / "config/workload-secret-authority.v1.json").read_text(
                encoding="utf-8"
            )
        )
        cls.monitoring = json.loads(
            (
                ROOT
                / "codestra/runtime-v1/keycloak-monitoring-readonly.v1.json"
            ).read_text(encoding="utf-8")
        )
        cls.generator = (
            ROOT / "scripts/generate_workload_policies.py"
        ).read_text(encoding="utf-8")

    def test_monitoring_identities_remain_distinct(self) -> None:
        prometheus = next(
            role
            for role in self.authority["roles"]
            if role["serviceIdentity"] == "prometheus-openbao"
        )
        self.assertEqual(self.authority["audience"], "openbao")
        self.assertEqual(
            prometheus["boundClaims"]["azp"],
            "prometheus-openbao",
        )
        self.assertEqual(
            self.monitoring["client"]["client_id"],
            "monitoring-readonly",
        )
        self.assertEqual(
            self.monitoring["client"]["audiences"],
            ["middleware-api"],
        )
        self.assertIn(
            "metrics.read",
            self.monitoring["client"]["optional_client_scopes"],
        )
        self.assertIn(
            "does not own or request the Keycloak `metrics.read`",
            self.document,
        )
        self.assertIn(
            "`monitoring-readonly` is a distinct Keycloak service client",
            self.document,
        )

    def test_exact_policy_exceptions_are_documented(self) -> None:
        for expected in (
            'capabilities = ["read", "list"]',
            'path "auth/token/renew-self"',
            'path "auth/token/revoke-self"',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.generator)
        self.assertIn(
            "`read` and `list` on the matching admitted",
            self.document,
        )
        self.assertIn(
            "`update` on `auth/token/renew-self` and `auth/token/revoke-self`",
            self.document,
        )
        self.assertIn(
            "secret-data `create` or `update`",
            self.document,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

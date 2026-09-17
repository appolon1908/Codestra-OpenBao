"""The secret-reference contract is a pointer contract: it can never carry a value."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/validate_secret_references.py"
SPEC = importlib.util.spec_from_file_location("validate_secret_references", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def load(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


class SecretReferenceContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = load("contracts/secret-reference.v1.schema.json")
        self.catalog = load("config/secret-references.v1.json")
        self.authority = load("config/workload-secret-authority.v1.json")
        self.prefixes = MODULE.admitted_prefixes(self.authority)
        self.valid = copy.deepcopy(self.catalog["references"][0])

    def errors_for(self, reference: dict) -> list[str]:
        return MODULE.validate_reference(reference, self.schema, self.prefixes, "ref")

    def test_reviewed_catalog_passes(self) -> None:
        self.assertEqual(MODULE.validate_catalog(self.catalog, self.schema, self.authority), [])

    def test_catalog_covers_every_monitoring_identity(self) -> None:
        identities = {reference["workload_identity"] for reference in self.catalog["references"]}
        for required in (
            "middleware-api", "prometheus-openbao", "alertmanager-runtime", "grafana-runtime",
            "alloy-collector", "otel-gateway", "loki-runtime", "tempo-runtime",
            "redis-exporter", "postgres-exporter", "superset-analytics",
        ):
            self.assertIn(required, identities)
        for environment in ("staging", "production"):
            self.assertTrue(any(r["environment"] == environment for r in self.catalog["references"]))

    def test_value_bearing_keys_are_rejected_at_any_depth(self) -> None:
        for key in ("value", "password", "token", "private_key", "client_secret", "root_token"):
            reference = copy.deepcopy(self.valid)
            reference[key] = "x"
            self.assertTrue(any("forbidden key" in e or "unknown properties" in e for e in self.errors_for(reference)), key)
        reference = copy.deepcopy(self.valid)
        reference["lease_metadata"] = {"ttl_seconds": 60, "db_password": "x"}
        self.assertTrue(any("forbidden key" in e for e in self.errors_for(reference)))

    def test_secret_shaped_values_are_rejected(self) -> None:
        reference = copy.deepcopy(self.valid)
        reference["purpose"] = "hvs." + "A" * 40
        self.assertTrue(any("secret-shaped" in e for e in self.errors_for(reference)))

    def test_reference_must_stay_inside_its_environment(self) -> None:
        reference = copy.deepcopy(self.valid)
        reference["environment"] = "production"
        reference["secret_ref"] = "codestra/staging/middleware/api/database"
        reference["reference_uri"] = "openbao://" + reference["secret_ref"]
        self.assertTrue(any("outside environment" in e for e in self.errors_for(reference)))

    def test_reference_must_lie_beneath_an_admitted_prefix(self) -> None:
        reference = copy.deepcopy(self.valid)
        reference["workload_identity"] = "n8n-automation"
        self.assertTrue(any("outside the prefixes admitted" in e for e in self.errors_for(reference)))
        reference["workload_identity"] = "unknown-service"
        self.assertTrue(any("is not admitted" in e for e in self.errors_for(reference)))

    def test_development_only_identity_is_not_admitted_in_staging(self) -> None:
        reference = copy.deepcopy(self.valid)
        reference["environment"] = "development"
        reference["secret_ref"] = "codestra/development/observability/grafana/oidc-client"
        reference["reference_uri"] = "openbao://" + reference["secret_ref"]
        reference["workload_identity"] = "grafana-runtime"
        self.assertTrue(any("is not admitted in development" in e for e in self.errors_for(reference)))

    def test_uri_must_match_reference(self) -> None:
        reference = copy.deepcopy(self.valid)
        reference["reference_uri"] = "openbao://codestra/staging/middleware/api/other"
        self.assertTrue(any("reference_uri" in e for e in self.errors_for(reference)))

    def test_wildcards_and_traversal_are_rejected(self) -> None:
        for bad in ("codestra/staging/middleware/api/*", "codestra/staging/../production/x", "codestra/staging//x", "codestra/staging"):
            reference = copy.deepcopy(self.valid)
            reference["secret_ref"] = bad
            reference.pop("reference_uri", None)
            self.assertTrue(any("malformed secret_ref" in e for e in self.errors_for(reference)), bad)

    def test_schema_forbidden_keys_match_validator(self) -> None:
        self.assertEqual(set(self.schema["x-codestra-forbidden-keys"]), set(MODULE.FORBIDDEN_KEYS))


if __name__ == "__main__":
    unittest.main()

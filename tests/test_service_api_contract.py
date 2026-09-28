from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "codestra/api/service-contract.v1.json"
AUTHORITY_SHA = "3517fb3b9bb1077d92419a5c13c07d703ffbebf6"

EXPECTED = {
    "health": ("GET", "/v1/sys/health", "read_only"),
    "readiness": ("GET", "/v1/sys/health", "read_only"),
    "seal-status": ("GET", "/v1/sys/seal-status", "read_only"),
    "leader": ("GET", "/v1/sys/leader", "read_only"),
    "metrics": ("GET", "/v1/sys/metrics", "read_only"),
    "workload-login": ("POST", "/v1/auth/jwt-codestra/login", "mutation"),
    "secret-read": ("GET", "/v1/codestra/data/{environment}/{namespace}/{secret-name}", "query"),
    "secret-metadata": ("GET", "/v1/codestra/metadata/{environment}/{namespace}/{secret-name}", "query"),
    "secret-write": ("POST", "/v1/codestra/data/{environment}/{namespace}/{secret-name}", "mutation"),
    "token-renew-self": ("POST", "/v1/auth/token/renew-self", "mutation"),
    "token-revoke-self": ("POST", "/v1/auth/token/revoke-self", "mutation"),
    "pki-issue": ("POST", "/v1/{mount}/issue/{role}", "mutation"),
}
SENSITIVE = {
    "workload-login",
    "secret-read",
    "secret-metadata",
    "secret-write",
    "token-renew-self",
    "token-revoke-self",
    "pki-issue",
}


class ServiceApiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        cls.operations = {item["id"]: item for item in cls.contract["nativeApi"]["operations"]}

    def test_complete_native_endpoint_inventory(self) -> None:
        self.assertEqual(set(self.operations), set(EXPECTED))
        for operation_id, (method, path, access) in EXPECTED.items():
            operation = self.operations[operation_id]
            with self.subTest(operation=operation_id):
                self.assertEqual(operation["method"], method)
                self.assertEqual(operation["path"], path)
                self.assertEqual(operation["access"], access)
                self.assertFalse(operation["controlPlaneProxyAllowed"])

    def test_sensitive_endpoints_are_never_control_plane_proxied(self) -> None:
        for operation_id in SENSITIVE:
            with self.subTest(operation=operation_id):
                self.assertFalse(self.operations[operation_id]["controlPlaneProxyAllowed"])

    def test_management_readback_is_health_only_and_secret_safe(self) -> None:
        management = self.contract["managementReadback"]
        self.assertFalse(management["allowsMutation"])
        self.assertFalse(management["exposesSecretValues"])
        self.assertEqual(management["responseBodyPolicy"], "discard")
        self.assertEqual(
            {management["healthOperationId"], management["readinessOperationId"]},
            {"health", "readiness"},
        )
        self.assertTrue(self.contract["safety"]["secretValueReadbackEnabled"] is False)
        self.assertTrue(self.contract["safety"]["nativeApiProxyEnabled"] is False)
        self.assertTrue(self.contract["safety"]["mutationProxyEnabled"] is False)

    def test_schema_authority_is_exact_and_current(self) -> None:
        self.assertEqual(
            self.contract["schemaAuthority"],
            {
                "path": "codestra/api/service-contract.schema.json",
                "repository": "ingtrader21-spec/Codestra-Telemetry",
                "sourceRevision": AUTHORITY_SHA,
                "version": "1.0.0",
            },
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

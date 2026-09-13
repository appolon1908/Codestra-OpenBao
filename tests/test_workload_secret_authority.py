from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "openbao_validator", ROOT / "scripts" / "validate_workload_secret_authority.py"
)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class WorkloadSecretAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads(VALIDATOR.POLICY.read_text(encoding="utf-8"))

    def reject(self, policy: dict) -> None:
        with self.assertRaises(SystemExit):
            VALIDATOR.validate(policy)

    def test_canonical_policy_passes(self) -> None:
        VALIDATOR.validate(copy.deepcopy(self.policy))

    def test_runtime_activation_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["runtimeApplyAuthorized"] = True
        self.reject(policy)

    def test_boolean_schema_version_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["schemaVersion"] = True
        self.reject(policy)

    def test_cross_environment_path_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        role = next(item for item in policy["roles"] if item["environment"] == "staging")
        role["pathPrefixes"] = ["codestra/production/middleware/"]
        self.reject(policy)

    def test_environment_claim_drift_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        role = next(item for item in policy["roles"] if item["environment"] == "staging")
        role["boundClaims"]["codestra_environment"] = "production"
        self.reject(policy)

    def test_environment_root_path_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        role = next(item for item in policy["roles"] if item["environment"] == "production")
        role["pathPrefixes"] = ["codestra/production/"]
        self.reject(policy)

    def test_cross_service_path_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        role = next(
            item for item in policy["roles"]
            if item["serviceIdentity"] == "kong-gateway"
            and item["environment"] == "production"
        )
        role["pathPrefixes"] = ["codestra/production/middleware/api/"]
        self.reject(policy)

    def test_wildcard_path_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["roles"][0]["pathPrefixes"] = ["codestra/production/*/"]
        self.reject(policy)

    def test_n8n_provider_secret_access_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        role = next(
            item for item in policy["roles"]
            if item["environment"] == "production"
            and item["serviceIdentity"] == "n8n-automation"
        )
        role["pathPrefixes"] = ["codestra/production/telnexa/"]
        self.reject(policy)

    def test_plaintext_environment_injection_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["secretInjection"]["environmentVariablesAllowed"] = True
        self.reject(policy)

    def test_static_kv_lease_model_drift_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["secretInjection"]["staticKvSecretLeaseRenewalRequired"] = True
        self.reject(policy)

        policy = copy.deepcopy(self.policy)
        policy["secretInjection"]["staticKvRerenderOnChangeRequired"] = False
        self.reject(policy)

        policy = copy.deepcopy(self.policy)
        policy["secretInjection"]["agentAuthTokenRenewalRequired"] = False
        self.reject(policy)

    def test_dynamic_secret_lease_controls_are_required(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["secretInjection"]["dynamicSecretLeaseRenewalRequired"] = False
        self.reject(policy)

        policy = copy.deepcopy(self.policy)
        policy["secretInjection"]["dynamicSecretRevocationOnShutdownRequired"] = False
        self.reject(policy)

    def test_static_and_dynamic_evidence_are_distinguished(self) -> None:
        for required in (
            "agent_auth_token_accessor_hash",
            "secret_version",
            "dynamic_lease_id_hash_if_applicable",
        ):
            policy = copy.deepcopy(self.policy)
            policy["requiredEvidence"].remove(required)
            self.reject(policy)

    def test_cross_service_wildcard_role_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["roles"][0]["serviceIdentity"] = "all-services"
        self.reject(policy)


if __name__ == "__main__":
    unittest.main()

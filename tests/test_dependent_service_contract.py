from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "dependent_contract_validator",
    ROOT / "scripts/validate_dependent_service_contract.py",
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class DependentServiceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(VALIDATOR.CONTRACT_PATH.read_text(encoding="utf-8"))
        authority_bytes = VALIDATOR.AUTHORITY_PATH.read_bytes()
        cls.authority = json.loads(authority_bytes)
        cls.authority_blob_sha = VALIDATOR.git_blob_sha(authority_bytes)

    def reject(self, contract: dict | None = None, authority: dict | None = None) -> None:
        with self.assertRaises(SystemExit):
            VALIDATOR.validate(
                copy.deepcopy(contract if contract is not None else self.contract),
                copy.deepcopy(authority if authority is not None else self.authority),
                self.authority_blob_sha,
            )

    def consumer(self, contract: dict, repo: str) -> dict:
        return next(item for item in contract["consumers"] if item["repo"] == repo)

    def role(self, authority: dict, identity: str) -> dict:
        return next(
            item
            for item in authority["roles"]
            if item["environment"] == "production"
            and item["serviceIdentity"] == identity
        )

    def test_canonical_contract_passes(self) -> None:
        VALIDATOR.validate(
            copy.deepcopy(self.contract),
            copy.deepcopy(self.authority),
            self.authority_blob_sha,
        )

    def test_unknown_identity_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        self.consumer(contract, "ingtrader21-spec/telnexa")["access"][0][
            "identity"
        ] = "unknown-sms-adapter"
        self.reject(contract=contract)

    def test_prefix_drift_and_parent_broadening_are_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        self.consumer(contract, "ingtrader21-spec/klyrow.com")["access"][0][
            "prefixes"
        ] = ["codestra/production/middleware/worker/email/other/"]
        self.reject(contract=contract)

        contract = copy.deepcopy(self.contract)
        self.consumer(contract, "ingtrader21-spec/klyrow.com")["access"][0][
            "prefixes"
        ] = ["codestra/production/middleware/worker/email/"]
        self.reject(contract=contract)

    def test_cross_environment_prefix_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        self.consumer(contract, "ingtrader21-spec/telnexa")["access"][0][
            "prefixes"
        ] = ["codestra/staging/middleware/worker/sms/telnexa/"]
        self.reject(contract=contract)

    def test_non_read_privilege_is_rejected(self) -> None:
        authority = copy.deepcopy(self.authority)
        self.role(authority, "telnexa-sms-adapter")["operations"] = [
            "read",
            "list",
            "create",
            "update",
            "delete",
        ]
        self.reject(authority=authority)

    def test_observability_provider_credentials_are_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        self.consumer(contract, "ingtrader21-spec/Codestra-Prometheus")["access"][0][
            "prefixes"
        ] = ["codestra/production/middleware/worker/sms/telnexa/"]
        self.reject(contract=contract)

    def test_odoo_business_data_contract_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        self.consumer(contract, "ingtrader21-spec/Odoo")[
            "constraint"
        ] = "credentials and business records"
        self.reject(contract=contract)

    def test_browser_facing_consumer_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        self.consumer(contract, "ingtrader21-spec/klyrow.com")[
            "repo"
        ] = "ingtrader21-spec/Klyrow-frontend"
        self.reject(contract=contract)

    def test_runtime_activation_and_business_effects_are_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["authority_binding"]["runtime_binding_authorized"] = True
        self.reject(contract=contract)

        authority = copy.deepcopy(self.authority)
        self.role(authority, "vicidial-adapter")[
            "providerBusinessEffectsEnabled"
        ] = True
        self.reject(authority=authority)

    def test_direct_roles_for_read_only_integrations_are_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["consumers"].append(
            {
                "repo": "ingtrader21-spec/Codestra-Grafana-",
                "access": [
                    {
                        "identity": "prometheus-openbao",
                        "prefixes": [
                            "codestra/production/observability/openbao/metrics-client/"
                        ],
                    }
                ],
            }
        )
        self.reject(contract=contract)

    def test_alternative_initializer_or_apply_path_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["canonical_framework"]["initialize"] = "scripts/bootstrap.sh"
        self.reject(contract=contract)

        contract = copy.deepcopy(self.contract)
        contract["canonical_framework"]["apply"] = "scripts/apply.sh"
        self.reject(contract=contract)

    def test_authority_blob_drift_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["authority_binding"]["source_blob_sha"] = "0" * 40
        self.reject(contract=contract)


if __name__ == "__main__":
    unittest.main(verbosity=2)

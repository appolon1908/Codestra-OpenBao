#!/usr/bin/env python3
"""Prove the native service API contract validator accepts the source and rejects drift."""

from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_codestra_service_contract", ROOT / "scripts/validate_codestra_service_contract.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ServiceApiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inputs = MODULE.load_inputs()

    def mutated(self) -> "MODULE.Inputs":
        return copy.deepcopy(self.inputs)

    def contract_operation(self, inputs, identifier: str) -> dict:
        return next(item for item in inputs.contract["nativeApi"]["operations"] if item["id"] == identifier)

    def authority_operation(self, inputs, identifier: str) -> dict:
        return next(item for item in inputs.authority["operations"] if item["operationId"] == identifier)

    def assert_rejected(self, inputs, fragment: str) -> None:
        with self.assertRaises(MODULE.ContractError) as context:
            MODULE.validate_inputs(inputs)
        self.assertIn(fragment, str(context.exception))

    # --- accepted source ---------------------------------------------------

    def test_committed_source_is_accepted(self) -> None:
        summary = MODULE.validate_inputs(self.mutated())
        self.assertEqual(summary["operations"], len(self.inputs.contract["nativeApi"]["operations"]))
        self.assertGreaterEqual(summary["operations"], 40)
        self.assertEqual(summary["callerClasses"], len(self.inputs.authority["callerClasses"]))

    def test_complete_governed_surface_is_declared(self) -> None:
        operations = {item["id"]: item for item in self.inputs.contract["nativeApi"]["operations"]}
        expected_paths = {
            "jwt-login": "/v1/auth/jwt-codestra/login",
            "oidc-callback": "/v1/auth/oidc/oidc/callback",
            "kv-read": "/v1/codestra/data/{environment}/{namespace}/{key}",
            "pki-issue": "/v1/pki-codestra/issue/{role}",
            "transit-decrypt": "/v1/transit-codestra/decrypt/{key}",
            "database-creds": "/v1/database/creds/{role}",
            "init": "/v1/sys/init",
            "unseal": "/v1/sys/unseal",
            "raft-snapshot": "/v1/sys/storage/raft/snapshot",
            "raft-snapshot-restore": "/v1/sys/storage/raft/snapshot-force",
            "lease-renew": "/v1/sys/leases/renew",
        }
        for identifier, path in expected_paths.items():
            self.assertEqual(operations[identifier]["path"], path, identifier)
        for identifier in ("init", "unseal", "kv-write", "policy-write", "jwt-role-write", "raft-snapshot-restore"):
            self.assertEqual(operations[identifier]["access"], "mutation", identifier)
            self.assertFalse(self.authority_operation(self.inputs, identifier)["grantedToWorkloads"], identifier)

    def test_workload_grants_are_exactly_the_generated_read_surface(self) -> None:
        granted = {
            row["operationId"] for row in self.inputs.authority["operations"] if row["grantedToWorkloads"]
        }
        self.assertEqual(
            granted,
            {
                "metrics", "jwt-login", "token-lookup-self", "token-renew-self", "token-revoke-self",
                "kv-read", "kv-metadata-read", "kv-metadata-list",
            },
        )
        self.assertEqual(self.authority_operation(self.inputs, "metrics")["workloadIdentityScope"], ["prometheus-openbao"])

    def test_secret_bearing_operations_never_reach_the_control_plane(self) -> None:
        for row in self.inputs.authority["operations"]:
            if row["secretBearingResponse"]:
                self.assertNotIn("control-plane-readback", row["callerClasses"], row["operationId"])
                self.assertEqual(self.contract_operation(self.inputs, row["operationId"])["responseBodyPolicy"], "native")

    # --- contract structure ------------------------------------------------

    def test_unknown_contract_field_is_rejected(self) -> None:
        inputs = self.mutated()
        inputs.contract["notes"] = "extra"
        self.assert_rejected(inputs, "canonical schema exactly")

    def test_unknown_operation_field_is_rejected(self) -> None:
        inputs = self.mutated()
        self.contract_operation(inputs, "health")["owner"] = "platform-security"
        self.assert_rejected(inputs, "exactly the schema fields")

    def test_control_plane_proxy_can_never_be_enabled(self) -> None:
        inputs = self.mutated()
        self.contract_operation(inputs, "kv-read")["controlPlaneProxyAllowed"] = True
        self.assert_rejected(inputs, "never be proxied")

    def test_timeout_outside_schema_range_is_rejected(self) -> None:
        inputs = self.mutated()
        self.contract_operation(inputs, "init")["timeoutMs"] = 60000
        self.assert_rejected(inputs, "between 250 and 10000")

    def test_duplicate_operation_id_is_rejected(self) -> None:
        inputs = self.mutated()
        inputs.contract["nativeApi"]["operations"].append(copy.deepcopy(self.contract_operation(inputs, "leader")))
        self.assert_rejected(inputs, "duplicated")

    def test_pki_issue_must_target_declared_mount(self) -> None:
        inputs = self.mutated()
        self.contract_operation(inputs, "pki-issue")["path"] = "/v1/pki-codestra/sign/{role}"
        self.assert_rejected(inputs, "declared PKI mount")

    def test_safety_flags_must_remain_false(self) -> None:
        inputs = self.mutated()
        inputs.contract["safety"]["runtimeActivationAuthorized"] = True
        self.assert_rejected(inputs, "safety flag")

    # --- authority map -----------------------------------------------------

    def test_authority_and_contract_must_list_the_same_operations(self) -> None:
        inputs = self.mutated()
        inputs.authority["operations"] = [row for row in inputs.authority["operations"] if row["operationId"] != "unseal"]
        self.assert_rejected(inputs, "same operations")

    def test_workload_grant_must_exist_in_generated_policies(self) -> None:
        inputs = self.mutated()
        row = self.authority_operation(inputs, "database-creds")
        row["grantedToWorkloads"] = True
        row["callerClasses"] = ["workload"]
        self.assert_rejected(inputs, "no generated policy provides")

    def test_write_capability_cannot_be_claimed_for_workloads(self) -> None:
        inputs = self.mutated()
        row = self.authority_operation(inputs, "kv-write")
        row["grantedToWorkloads"] = True
        row["callerClasses"] = ["workload", "operator"]
        self.assert_rejected(inputs, "no generated policy provides")

    def test_metrics_grant_is_limited_to_prometheus_identity(self) -> None:
        inputs = self.mutated()
        self.authority_operation(inputs, "metrics")["workloadIdentityScope"] = ["kong-gateway"]
        self.assert_rejected(inputs, "limited to identities")

    def test_generated_policies_must_keep_explicit_denies(self) -> None:
        inputs = self.mutated()
        name = next(iter(inputs.rendered_policies))
        inputs.rendered_policies[name] = inputs.rendered_policies[name].replace(
            'path "sys/*" {\n  capabilities = ["deny"]\n}\n', ""
        )
        self.assert_rejected(inputs, "requires an explicit deny")

    def test_generated_policy_grant_contradicting_the_map_is_rejected(self) -> None:
        inputs = self.mutated()
        name = next(iter(inputs.rendered_policies))
        inputs.rendered_policies[name] += '\npath "sys/leases/renew" {\n  capabilities = ["update"]\n}\n'
        self.assert_rejected(inputs, "is not granted to workloads but")

    def test_mutation_can_never_be_read_back_by_the_control_plane(self) -> None:
        inputs = self.mutated()
        self.authority_operation(inputs, "kv-write")["callerClasses"].append("control-plane-readback")
        self.assert_rejected(inputs, "never be reached by the control plane")

    def test_secret_bearing_response_requires_native_body_policy(self) -> None:
        inputs = self.mutated()
        self.contract_operation(inputs, "kv-read")["responseBodyPolicy"] = "metadata_only"
        self.assert_rejected(inputs, "native body policy")

    def test_oidc_plan_redirect_must_target_served_callback(self) -> None:
        inputs = self.mutated()
        inputs.oidc_plan["client"]["redirectUris"] = [
            uri.replace("/v1/auth/oidc/oidc/callback", "/v1/auth/oidc/callback")
            for uri in inputs.oidc_plan["client"]["redirectUris"]
        ]
        self.assert_rejected(inputs, "redirect URIs")

    def test_undeclared_mount_is_rejected(self) -> None:
        inputs = self.mutated()
        inputs.authority["mounts"]["ssh"] = {"type": "ssh", "source": "config/secrets/engines.v1.json", "status": "PREPARED_DISABLED"}
        self.assert_rejected(inputs, "not declared in config/secrets/engines.v1.json")

    def test_operation_path_must_stay_inside_its_mount(self) -> None:
        inputs = self.mutated()
        self.contract_operation(inputs, "kv-read")["path"] = "/v1/kv-platform/data/{key}"
        self.assert_rejected(inputs, "outside mount")

    def test_missing_evidence_is_rejected(self) -> None:
        inputs = self.mutated()
        self.authority_operation(inputs, "init")["evidence"].append("docs/DOES-NOT-EXIST.md")
        self.assert_rejected(inputs, "cites missing file")

    def test_unauthenticated_flag_is_limited_to_login_paths(self) -> None:
        inputs = self.mutated()
        self.authority_operation(inputs, "kv-read")["unauthenticatedPath"] = True
        self.assert_rejected(inputs, "only be unauthenticated")

    def test_runtime_authorization_flags_must_remain_false(self) -> None:
        inputs = self.mutated()
        inputs.authority["runtimeApplyAuthorized"] = True
        self.assert_rejected(inputs, "must remain false")

    # --- documentation -----------------------------------------------------

    def test_document_table_must_match_contract(self) -> None:
        inputs = self.mutated()
        inputs.document = inputs.document.replace("| `POST` | `/v1/sys/init` |", "| `POST` | `/v1/sys/initialise` |")
        self.assert_rejected(inputs, "does not match the contract")

    def test_document_must_describe_every_caller_class(self) -> None:
        inputs = self.mutated()
        inputs.document = inputs.document.replace("| `auditor` |", "| `reviewer` |")
        self.assert_rejected(inputs, "every caller class")


if __name__ == "__main__":
    unittest.main()

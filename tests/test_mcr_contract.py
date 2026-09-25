"""Offline security contract tests; fixtures contain identifiers, never secrets."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts import mcr_contract as mcr

ROOT = Path(__file__).resolve().parents[1]


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads((ROOT / "config/mcr-secret-contract.v1.json").read_text())

    def reject(self, contract):
        with self.assertRaises(mcr.ContractError):
            mcr.validate(contract)

    def test_fixture_and_all_classes(self):
        refs = mcr.validate(self.contract)
        self.assertEqual({r.credential_class for r in refs}, set(mcr.CLASSES))
        self.assertTrue(all(isinstance(r, mcr.SecretReference) for r in refs))

    def test_closed_fields_and_missing_fields_recursively(self):
        def objects(value, path=()):
            if isinstance(value, dict):
                yield path, value
                for key, child in value.items():
                    yield from objects(child, path + (key,))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    yield from objects(child, path + (index,))
        for path, obj in objects(self.contract):
            for key in [None, *obj]:
                with self.subTest(path=path, key=key):
                    changed = copy.deepcopy(self.contract)
                    target = changed
                    for part in path:
                        target = target[part]
                    if key is None:
                        target["value"] = "synthetic-rejected-marker"
                    else:
                        del target[key]
                    self.reject(changed)

    def test_reject_wrong_types_recursively(self):
        def leaves(value, path=()):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield from leaves(child, path + (key,))
            elif isinstance(value, list):
                for i, child in enumerate(value):
                    yield from leaves(child, path + (i,))
            else:
                yield path, value
        for path, value in leaves(self.contract):
            for bad in [None, [], {}, 1.5, True if type(value) is int else 1]:
                with self.subTest(path=path, bad=bad):
                    changed = copy.deepcopy(self.contract)
                    target = changed
                    for part in path[:-1]:
                        target = target[part]
                    target[path[-1]] = bad
                    self.reject(changed)

    def test_identifiers_and_reference_fullmatch(self):
        for binding in self.contract["bindings"]:
            for key in ["id", "tenant", "service", "owner", "field", *binding["scope"]]:
                for bad in ["", ".", "..", "a/b", "a\\b", "%2f", "a b", "*", "+", "{x}", 'a"', "a\n", "é", "a" * 65]:
                    changed = copy.deepcopy(self.contract)
                    target = changed["bindings"][self.contract["bindings"].index(binding)]
                    (target["scope"] if key in target["scope"] else target)[key] = bad
                    self.reject(changed)
        for key in ["reference", "logical_path"]:
            for suffix in ["\n", "/*", "/../other", "%2f", "?version=2"]:
                changed = copy.deepcopy(self.contract)
                changed["bindings"][0][key] += suffix
                self.reject(changed)

    def test_scope_and_path_binding_every_class(self):
        for index, binding in enumerate(self.contract["bindings"]):
            for key in ["tenant", "environment", "service", "owner", *binding["scope"]]:
                changed = copy.deepcopy(self.contract)
                target = changed["bindings"][index]
                (target["scope"] if key in binding["scope"] else target)[key] = "foreign"
                self.reject(changed)
            for path in ["sys/policies/acl", "codestra/metadata/staging/x", "other/data/staging/x"]:
                changed = copy.deepcopy(self.contract)
                changed["bindings"][index]["logical_path"] = path
                self.reject(changed)

    def test_duplicate_ids_paths_and_versions(self):
        changed = copy.deepcopy(self.contract)
        changed["bindings"].append(copy.deepcopy(changed["bindings"][0]))
        self.reject(changed)
        changed["bindings"][-1]["id"] = "another-id"
        self.reject(changed)
        for bad in [0, -1, True, "1", 1.0]:
            changed = copy.deepcopy(self.contract)
            changed["bindings"][0]["version"] = bad
            self.reject(changed)

    def test_trusted_identity_and_ownership_are_separate(self):
        for ref in mcr.validate(self.contract):
            if ref.registration_required:
                with self.assertRaises(mcr.ContractError):
                    mcr.authorize(ref, mcr.WorkloadIdentity(ref.environment, ref.tenant, ref.service), [ref])
                continue
            identity = mcr.WorkloadIdentity(ref.environment, ref.tenant, ref.service)
            self.assertEqual(mcr.authorize(ref, identity, [ref]), ref)
            for identity in [mcr.WorkloadIdentity("production", ref.tenant, ref.service),
                             mcr.WorkloadIdentity(ref.environment, "foreign", ref.service),
                             mcr.WorkloadIdentity(ref.environment, ref.tenant, "planner")]:
                with self.assertRaises(mcr.ContractError):
                    mcr.authorize(ref, identity, [ref])
            with self.assertRaises(mcr.ContractError):
                mcr.authorize(ref, mcr.WorkloadIdentity(ref.environment, ref.tenant, ref.service), [])

    def test_policy_composition_is_exact(self):
        ref = mcr.validate(self.contract)[0]
        expected = mcr.policy_grants(ref)
        mcr.validate_policy_composition(ref, [expected])
        for path, capabilities in [("sys/*", ["read"]), ("auth/token/create", ["update"]),
                                   (ref.data_path, ["read", "list"]),
                                   (ref.data_path, ["write"]), (ref.data_path, ["delete"]),
                                   ("codestra/data/*", ["read"]),
                                   (ref.data_path.replace("/data/", "/metadata/"), ["list"])]:
            with self.assertRaises(mcr.ContractError):
                mcr.validate_policy_composition(ref, [expected, {path: capabilities}])
        with self.assertRaises(mcr.ContractError):
            mcr.validate_policy_composition(ref, [])

    def test_security_requirements_cannot_be_weakened(self):
        for section in ["auth", "delivery", "rotation", "revocation", "audit", "readback", "recovery", "rollback", "readiness"]:
            for key, value in self.contract[section].items():
                changed = copy.deepcopy(self.contract)
                changed[section][key] = not value if type(value) is bool else "unsafe"
                self.reject(changed)
        for key in self.contract["gates"]:
            changed = copy.deepcopy(self.contract)
            changed["gates"][key] = True
            self.reject(changed)

    def test_ttl_rotation_and_static_lease_limits(self):
        for key, bad in [("token_ttl_seconds", 301), ("token_max_ttl_seconds", 301),
                         ("token_ttl_seconds", 0), ("token_max_ttl_seconds", 29),
                         ("jwt_max_ttl_seconds", 301), ("clock_skew_seconds", 31)]:
            changed = copy.deepcopy(self.contract)
            changed["auth"][key] = bad
            self.reject(changed)
        for index in range(len(self.contract["bindings"])):
            for key, bad in [("rotation_days", 91), ("rotation_days", 0),
                             ("provider_limit_days", 1), ("overlap_seconds", 0),
                             ("overlap_seconds", 86401), ("secret_lease_seconds", 300),
                             ("renewable_secret", True)]:
                changed = copy.deepcopy(self.contract)
                changed["bindings"][index]["lifecycle"][key] = bad
                self.reject(changed)

    def test_generator_determinism_pending_registration_and_drift(self):
        expected = mcr.generate(self.contract)
        changed = copy.deepcopy(self.contract)
        changed["bindings"].reverse()
        self.assertEqual(expected, mcr.generate(changed))
        for ref in mcr.validate(self.contract):
            self.assertEqual(ref.policy_name + ".hcl" in expected, not ref.registration_required)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name, content in expected.items():
                (directory / name).write_text(content)
            mcr.check_generated(self.contract, directory)
            name = next(iter(expected))
            (directory / name).write_text("stale")
            with self.assertRaises(mcr.ContractError):
                mcr.check_generated(self.contract, directory)
            (directory / name).write_text(expected[name])
            (directory / "legacy.hcl").write_text('path "*" {}')
            with self.assertRaises(mcr.ContractError):
                mcr.check_generated(self.contract, directory)

    def test_cli_sanitizes_rejected_json_and_duplicate_keys(self):
        for data in ['{"value":"synthetic-rejected-marker"}',
                     '{"schema_version":1,"schema_version":1}',
                     '{"synthetic-rejected-marker":', '{"schema_version":NaN}']:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "input.json"
                path.write_text(data)
                result = subprocess.run([sys.executable, "scripts/mcr_contract.py", "validate", "--contract", str(path)],
                                        cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, "MCR contract rejected\n")
                self.assertNotIn("synthetic-rejected-marker", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

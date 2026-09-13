#!/usr/bin/env python3
"""Regression tests for the fail-closed Orbit adoption contract."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/validate_orbit_adoption.py"
SPEC = importlib.util.spec_from_file_location("validate_orbit_adoption", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load Orbit adoption validator")
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


class OrbitAdoptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(
            (ROOT / "orbit/adoption-manifest.json").read_text(encoding="utf-8")
        )
        cls.schema = json.loads(
            (ROOT / "orbit/adoption-manifest.schema.json").read_text(encoding="utf-8")
        )

    def assert_manifest_rejected(self, mutate) -> None:
        document = copy.deepcopy(self.manifest)
        mutate(document)
        with self.assertRaises(VALIDATOR.OrbitAdoptionValidationError):
            VALIDATOR.validate_manifest(document)

    def test_current_contract_passes(self) -> None:
        VALIDATOR.validate_schema(copy.deepcopy(self.schema))
        VALIDATOR.validate_manifest(copy.deepcopy(self.manifest))
        VALIDATOR.validate_files()

    def test_cli_rejects_unsupported_arguments(self) -> None:
        with patch("builtins.print") as output:
            status = VALIDATOR.main(["unexpected"])
        self.assertEqual(status, 1)
        output.assert_called_once()
        self.assertIn(
            "does not accept command-line arguments",
            output.call_args.args[0],
        )

    def test_unapproved_target_branch_is_rejected(self) -> None:
        self.assert_manifest_rejected(
            lambda value: value.__setitem__("targetBranch", "development")
        )

    def test_noncanonical_adoption_mode_is_rejected(self) -> None:
        self.assert_manifest_rejected(
            lambda value: value.__setitem__(
                "adoptionMode", "native-operator-theme-sso"
            )
        )

    def test_candidate_or_certified_status_is_rejected(self) -> None:
        for status in ("candidate", "certified"):
            with self.subTest(status=status):
                self.assert_manifest_rejected(
                    lambda value, status=status: value.__setitem__("status", status)
                )

    def test_runtime_application_cannot_be_authorized(self) -> None:
        self.assert_manifest_rejected(
            lambda value: value["requirements"].__setitem__(
                "runtimeApplyAuthorized", True
            )
        )

    def test_native_ports_cannot_be_public(self) -> None:
        self.assert_manifest_rejected(
            lambda value: value["requirements"].__setitem__("nativePortsPublic", True)
        )

    def test_blocked_status_requires_blockers(self) -> None:
        self.assert_manifest_rejected(lambda value: value.__setitem__("blockers", []))

    def test_unknown_top_level_property_is_rejected(self) -> None:
        self.assert_manifest_rejected(
            lambda value: value.__setitem__("runtimeToken", "prohibited")
        )

    def test_schema_cannot_be_broadened(self) -> None:
        schema = copy.deepcopy(self.schema)
        schema["additionalProperties"] = True
        with self.assertRaises(VALIDATOR.OrbitAdoptionValidationError):
            VALIDATOR.validate_schema(schema)

    def test_schema_cannot_declare_an_unsupported_property(self) -> None:
        schema = copy.deepcopy(self.schema)
        schema["properties"]["credentials"] = {"type": "string"}
        with self.assertRaises(VALIDATOR.OrbitAdoptionValidationError):
            VALIDATOR.validate_schema(schema)

    def test_domain_must_remain_restricted_and_unverified(self) -> None:
        self.assert_manifest_rejected(
            lambda value: value.__setitem__("domainStatus", "registered")
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

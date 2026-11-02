from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from codestra.change_kernel import actuator
from codestra.change_kernel.kernel import KernelError


class ReadbackTests(unittest.TestCase):
    config = {"kind": "auth_config", "action": "update", "name": "auth/workload/config",
              "payload": {"bound_issuer": "https://issuer.example.invalid"}}
    plugin = {"kind": "auth_plugin", "action": "create", "name": "codestra-jwt-replay",
              "payload": {"name": "codestra-jwt-replay", "command": "codestra-jwt-replay",
                          "version": "v1.1.0", "sha256": "a" * 64}}

    def response(self, value=None, *, code=0, stderr="", raw=None):
        return subprocess.CompletedProcess(["bao"], code,
                                           raw if raw is not None else json.dumps(value), stderr)

    def assert_unavailable(self, result, operation=None):
        with patch("subprocess.run", return_value=result):
            with self.assertRaises(Exception) as caught:
                actuator.default_readback(operation or self.config)
        self.assertIsInstance(caught.exception, KernelError)
        self.assertEqual(caught.exception.code, "READBACK_UNAVAILABLE")
        self.assertNotIn("readback-sensitive-canary", str(caught.exception))

    def catalog(self):
        return {"auth": ["codestra-jwt-replay"], "details": [
            {"type": "auth", "name": "codestra-jwt-replay", "version": "v1.1.0", "builtin": False}]}

    def test_observed_resource_match_and_drift_are_distinguished(self):
        for issuer, expected in (("https://issuer.example.invalid", True), ("other-issuer", False)):
            with self.subTest(issuer=issuer), patch(
                    "subprocess.run", return_value=self.response({"data": {"bound_issuer": issuer}})):
                self.assertIs(actuator.default_readback(self.config), expected)

    def test_failed_reads_cannot_become_proof_of_absence(self):
        for stderr in (
            "Code: 403. Errors:\n\n* permission denied readback-sensitive-canary",
            "Code: 503. Errors:\n\n* sealed",
            "Code: 404. Errors:\n\n* unsupported path",
            "connection refused",
            "No value found at another/path",
        ):
            with self.subTest(stderr=stderr):
                self.assert_unavailable(self.response(code=2, stderr=stderr))

    def test_malformed_json_and_resource_shapes_remain_unavailable(self):
        for raw in ("invalid", "[]", "null", '{"data": []}'):
            with self.subTest(raw=raw):
                self.assert_unavailable(self.response(raw=raw))

    def test_exact_command_specific_absence_still_permits_creation(self):
        policy = {"kind": "policy", "action": "create", "name": "reader",
                  "payload": {"policy": 'path "codestra/metadata/app" { capabilities = ["read"] }'}}
        for operation, stderr in (
            (self.config, "No value found at auth/workload/config\n"),
            (policy, "No policy named: reader\n"),
        ):
            with self.subTest(kind=operation["kind"]), patch(
                    "subprocess.run", return_value=self.response(code=2, stderr=stderr)):
                self.assertFalse(actuator.default_readback(operation))

    def test_empty_valid_catalog_proves_plugin_absence(self):
        with patch("subprocess.run", return_value=self.response({"auth": [], "details": []})):
            self.assertFalse(actuator.default_readback(self.plugin))

    def test_another_or_unversioned_catalog_entry_does_not_match_requested_version(self):
        for version in ("v1.0.0", ""):
            catalog = self.catalog()
            catalog["details"][0]["version"] = version
            with self.subTest(version=version), patch("subprocess.run", return_value=self.response(catalog)):
                self.assertFalse(actuator.default_readback(self.plugin))

    def test_catalog_presence_requires_exact_plugin_information(self):
        for checksum, expected in (("a" * 64, True), ("b" * 64, False)):
            info = {**self.plugin["payload"], "sha256": checksum, "builtin": False}
            with self.subTest(checksum=checksum), patch(
                    "subprocess.run", side_effect=[self.response(self.catalog()), self.response(info)]):
                self.assertIs(actuator.default_readback(self.plugin), expected)

    def test_unusable_catalog_or_failed_plugin_info_remains_unavailable(self):
        for catalog in ({}, {"auth": ["codestra-jwt-replay"], "details": []},
                        {"auth": [], "details": [{"type": "auth", "name": "unexpected"}]}):
            with self.subTest(catalog=catalog):
                self.assert_unavailable(self.response(catalog), self.plugin)
        with patch("subprocess.run", side_effect=[
                self.response(self.catalog()), self.response(code=2, stderr="permission denied")]):
            with self.assertRaises(Exception) as caught:
                actuator.default_readback(self.plugin)
        self.assertIsInstance(caught.exception, KernelError)
        self.assertEqual(caught.exception.code, "READBACK_UNAVAILABLE")

    def test_json_flags_precede_positional_arguments(self):
        cases = [
            (self.config, [self.response({"data": self.config["payload"]})],
             [["bao", "read", "-format=json", self.config["name"]]]),
            (self.plugin, [self.response(self.catalog()),
                           self.response({**self.plugin["payload"], "builtin": False})],
             [["bao", "plugin", "list", "-format=json", "auth"],
              ["bao", "plugin", "info", "-format=json", "-version=v1.1.0",
               "auth", "codestra-jwt-replay"]]),
        ]
        for operation, responses, expected in cases:
            with self.subTest(kind=operation["kind"]), patch("subprocess.run", side_effect=responses) as run:
                self.assertTrue(actuator.default_readback(operation))
                self.assertEqual([call.args[0] for call in run.call_args_list], expected)

    def test_present_malformed_mount_and_auth_entries_remain_unavailable(self):
        operations = [
            {"kind": "secret_engine", "name": "codestra/", "payload": {}},
            {"kind": "auth_method", "name": "codestra-jwt/", "payload": {
                "plugin_name": "codestra-jwt-replay", "plugin_version": "v1.1.0",
                "plugin_sha256": "a" * 64}},
        ]
        for operation in operations:
            for item in (None, [], {}, {"type": None}):
                with self.subTest(kind=operation["kind"], item=item):
                    self.assert_unavailable(self.response({operation["name"]: item}), operation)
            with self.subTest(kind=operation["kind"], missing=True), patch(
                    "subprocess.run", return_value=self.response({})):
                self.assertFalse(actuator.default_readback(operation))
        self.assert_unavailable(self.response({"codestra/": {"type": "kv", "options": []}}),
                                operations[0])

    def test_malformed_plugin_information_remains_unavailable(self):
        for item in ({}, {"name": "codestra-jwt-replay"},
                     {**self.plugin["payload"], "builtin": "false"},
                     {**self.plugin["payload"], "version": None, "builtin": False}):
            with self.subTest(item=item), patch("subprocess.run", side_effect=[
                    self.response(self.catalog()), self.response(item)]):
                with self.assertRaises(Exception) as caught:
                    actuator.default_readback(self.plugin)
                self.assertIsInstance(caught.exception, KernelError)
                self.assertEqual(caught.exception.code, "READBACK_UNAVAILABLE")

    def test_cli_entry_types_preserve_valid_drift_and_reject_malformed_metadata(self):
        mount = {"kind": "secret_engine", "name": "codestra/", "payload": {}}
        auth = {"kind": "auth_method", "name": "codestra-jwt/", "payload": {
            "plugin_name": "codestra-jwt-replay", "plugin_version": "v1.1.0",
            "plugin_sha256": "a" * 64}}
        for item in ({"type": ""}, {"type": "kv", "options": {"version": 2}}):
            with self.subTest(mount=item):
                self.assert_unavailable(self.response({mount["name"]: item}), mount)
        for item in ({"type": ""}, {"type": "jwt"},
                     {"type": "jwt", "plugin_version": "", "running_plugin_version": None,
                      "running_sha256": ""}):
            with self.subTest(auth=item):
                self.assert_unavailable(self.response({auth["name"]: item}), auth)
        with patch("subprocess.run", side_effect=[self.response(self.catalog()), self.response({
                **self.plugin["payload"], "name": "", "builtin": False})]):
            with self.assertRaises(KernelError) as caught:
                actuator.default_readback(self.plugin)
            self.assertEqual(caught.exception.code, "READBACK_UNAVAILABLE")
        cases = [
            (mount, {"type": "kv", "options": {"version": "2"}}, True),
            (mount, {"type": "kv", "options": None}, False),
            (auth, {"type": "codestra-jwt-replay", "plugin_version": "v1.1.0",
                    "running_plugin_version": "v1.1.0", "running_sha256": "a" * 64}, True),
            (auth, {"type": "jwt", "plugin_version": "", "running_plugin_version": "",
                    "running_sha256": ""}, False),
        ]
        for operation, item, expected in cases:
            with self.subTest(item=item), patch(
                    "subprocess.run", return_value=self.response({operation["name"]: item})) as run:
                self.assertIs(actuator.default_readback(operation), expected)
                expected_command = "secrets" if operation is mount else "auth"
                self.assertEqual(run.call_args.args[0], ["bao", expected_command, "list", "-format=json"])
        with patch("subprocess.run", side_effect=[self.response(self.catalog()), self.response({
                "name": "codestra-jwt-replay", "command": "", "version": "",
                "sha256": "", "builtin": True})]):
            self.assertFalse(actuator.default_readback(self.plugin))

    def test_missing_tool_and_timeout_remain_unavailable(self):
        for error in (FileNotFoundError("bao"), subprocess.TimeoutExpired(["bao", "read"], 120)):
            with self.subTest(error=type(error).__name__), patch("subprocess.run", side_effect=error):
                with self.assertRaises(Exception) as caught:
                    actuator.default_readback(self.config)
                self.assertIsInstance(caught.exception, KernelError)
                self.assertEqual(caught.exception.code, "READBACK_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main(verbosity=2)

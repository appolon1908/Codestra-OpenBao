"""Native source admission runs real offline checks without promotion authority."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    path = ROOT / "scripts" / (name + ".py")
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class NativeSourceTests(unittest.TestCase):
    def workflow(self):
        return yaml.safe_load((ROOT / ".github/workflows/agent-governance.yml").read_text())

    def test_native_job_checks_real_source_on_main_targets(self):
        workflow = self.workflow()
        events = workflow.get("on", workflow.get(True))
        self.assertEqual(events, {"pull_request": {"branches": ["main"]},
                                  "push": {"branches": ["main"]}})
        job = workflow["jobs"]["native-source"]
        self.assertEqual(job["name"], "OpenBao governance / source validation")
        self.assertEqual(job["runs-on"], "ubuntu-24.04")
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(workflow["env"]["EXPECTED_SHA"],
                         "${{ github.event.pull_request.head.sha || github.sha }}")
        commands = "\n".join(s.get("run", "") for s in job["steps"])
        for command in ("scripts/validate_native_source.py", "scripts/mcr_contract.py validate",
                        "scripts/mcr_contract.py check-generated", "unittest discover"):
            self.assertIn(command, commands)
        checkout = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@"))
        self.assertEqual(checkout["with"]["ref"], "${{ env.EXPECTED_SHA }}")
        self.assertFalse(checkout["with"]["persist-credentials"])
        self.assertEqual(checkout["with"]["fetch-depth"], 0)

    def test_installed_controller_source_jobs_are_retired(self):
        for name in ("codestra-hierarchy-governance.yml", "workstation-governance.yml"):
            self.assertFalse((ROOT / ".github/workflows" / name).exists())

    def test_workflows_reject_writes_self_hosted_and_privileged_events(self):
        validator = module("validate_native_source")
        self.assertIsNotNone(validator)
        good = self.workflow()
        validator.validate_workflow(good)
        for mutate in (
            lambda w: w.update(permissions={"contents": "write"}),
            lambda w: w.update({"on": {"pull_request_target": None}}),
            lambda w: w["jobs"]["native-source"].update(**{"runs-on": ["self-hosted"]}),
            lambda w: w["jobs"]["native-source"].update(**{"if": "false"}),
            lambda w: w["jobs"]["native-source"]["steps"][-1].update(**{"if": "false"}),
            lambda w: w.update(env={"TOKEN": "${{ secrets.RUNTIME_TOKEN }}"}),
            lambda w: w["jobs"]["native-source"]["steps"].append({"run": "git push origin HEAD:production"}),
            lambda w: w["jobs"]["native-source"]["steps"].append({"run": "git push --force origin HEAD:main"}),
            lambda w: w["jobs"]["native-source"]["steps"][0]["with"].update(**{"persist-credentials": True}),
        ):
            changed = copy.deepcopy(good)
            mutate(changed)
            with self.subTest(workflow=changed), self.assertRaises(ValueError):
                validator.validate_workflow(changed)

    def test_source_syntax_rejects_malformed_and_duplicate_data(self):
        validator = module("validate_native_source")
        self.assertIsNotNone(validator)
        for suffix, content in ((".json", '{"flag":false,"flag":true}'),
                                (".json", '{"flag":NaN}'), (".json", '{broken'),
                                (".yml", 'flag: [unclosed'), (".py", 'def broken('),
                                (".sh", 'if true; then')):
            with self.subTest(suffix=suffix, content=content), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / ("fixture" + suffix)
                path.write_text(content)
                with self.assertRaises((ValueError, SyntaxError, subprocess.CalledProcessError, yaml.YAMLError)):
                    validator.validate_file(path)

    def test_production_defaults_cannot_be_enabled(self):
        validator = module("validate_native_source")
        self.assertIsNotNone(validator)
        files = validator.safety_documents(ROOT)
        validator.validate_safety(files)
        for path, key in (("CODESTRA_UPSTREAM.json", "deployment_enabled"),
                          ("CODESTRA_UPSTREAM.json", "secret_material_allowed_in_git"),
                          (".governance/authority.json", "allow_force_push"),
                          (".governance/authority.json", "allow_production_effects"),
                          ("monitoring-integration.v1.json", "activation_enabled")):
            changed = copy.deepcopy(files)
            changed[path][key] = True
            with self.subTest(path=path, key=key), self.assertRaises(ValueError):
                validator.validate_safety(changed)

    def test_upstream_intake_is_read_only_and_never_imports_or_pushes(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/upstream-source-sync.yml").read_text())
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        commands = "\n".join(s.get("run", "") for j in workflow["jobs"].values() for s in j["steps"])
        self.assertIn("scripts/inspect_upstream_source.py", commands)
        self.assertNotRegex(commands, r"git\s+(?:push|commit|pull)|--force|rm -rf|docker|deploy")
        inspector = module("inspect_upstream_source")
        self.assertIsNotNone(inspector)
        ref = "refs/heads/main"
        self.assertEqual(inspector.parse_remote_oid("a" * 40 + "\t" + ref + "\n", ref), "a" * 40)
        for output in ("", "main\t" + ref, "a" * 40 + "\trefs/heads/other",
                       ("a" * 40 + "\t" + ref + "\n") * 2):
            with self.subTest(output=output), self.assertRaises(ValueError):
                inspector.parse_remote_oid(output, ref)

    def test_upstream_report_is_bound_and_explicitly_not_security_acceptance(self):
        inspector = module("inspect_upstream_source")
        self.assertIsNotNone(inspector)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
            (root / "CODESTRA_UPSTREAM.json").write_text(json.dumps(manifest))
            output = root / "report.json"
            with mock.patch.object(inspector, "ROOT", root), \
                 mock.patch.dict(os.environ, {"EXPECTED_SHA": "a" * 40}), \
                 mock.patch("sys.argv", ["inspect", "--output", str(output)]), \
                 mock.patch.object(inspector.subprocess, "check_output", side_effect=[
                     "a" * 40 + "\n", "b" * 40 + "\trefs/heads/main\n"]) as git:
                inspector.main()
            report = json.loads(output.read_text())
            self.assertEqual(report["source_sha"], "a" * 40)
            self.assertEqual(report["upstream_commit"], "b" * 40)
            for field in ("source_imported", "security_verified", "protected_ref_updated", "runtime_authorized"):
                self.assertIs(report[field], False)
            self.assertEqual(git.call_args_list[-1].args[0],
                             ["git", "ls-remote", "--exit-code", "https://github.com/openbao/openbao.git", "refs/heads/main"])

    def test_upstream_wrong_checkout_or_untrusted_authority_fails_before_network(self):
        inspector = module("inspect_upstream_source")
        self.assertIsNotNone(inspector)
        for expected, url in (("b" * 40, "https://github.com/openbao/openbao.git"),
                              ("a" * 40, "https://example.invalid/untrusted.git")):
            with self.subTest(expected=expected, url=url), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                manifest = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
                manifest["upstream_clone_url"] = url
                (root / "CODESTRA_UPSTREAM.json").write_text(json.dumps(manifest))
                with mock.patch.object(inspector, "ROOT", root), \
                     mock.patch.dict(os.environ, {"EXPECTED_SHA": expected}), \
                     mock.patch("sys.argv", ["inspect", "--output", str(root / "report.json")]), \
                     mock.patch.object(inspector.subprocess, "check_output", return_value="a" * 40 + "\n") as git:
                    with self.assertRaises(ValueError):
                        inspector.main()
                    self.assertEqual(git.call_count, 1)
                self.assertFalse((root / "report.json").exists())


class CommittedIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git("init", "-q")
        for key, value in (("user.name", "Fixture"), ("user.email", "fixture@example.invalid"),
                           ("commit.gpgsign", "false"), ("core.hooksPath", "/dev/null")):
            self.git("config", key, value)
        self.base = self.commit("base\n")
        self.head = self.commit("candidate\n")

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True).strip()

    def commit(self, content):
        (self.root / "file.txt").write_text(content)
        self.git("add", "file.txt")
        self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def validate(self, base=None, head=None):
        validator = module("validate_native_source")
        self.assertIsNotNone(validator)
        validator.validate_identity(self.root, base or self.base, head or self.head)

    def test_clean_committed_range_passes(self):
        self.validate()

    def test_committed_whitespace_is_rejected_with_clean_checkout(self):
        self.head = self.commit("defect \n")
        self.assertEqual(self.git("status", "--porcelain"), "")
        with self.assertRaises(subprocess.CalledProcessError):
            self.validate()

    def test_wrong_head_and_unknown_or_symbolic_base_are_rejected(self):
        for base, head in ((self.base, self.base), ("a" * 40, self.head), ("HEAD", self.head)):
            with self.subTest(base=base, head=head), self.assertRaises((ValueError, subprocess.CalledProcessError)):
                self.validate(base, head)


if __name__ == "__main__":
    unittest.main()

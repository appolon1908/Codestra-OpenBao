"""Keep atomic source CI runnable without giving it promotion or runtime authority."""
from __future__ import annotations

import fnmatch
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/atomic-source-ci.yml"
BRANCH = "atomic/ob-15-cicd--04-promotion--pr109-reconcile-20261016"


class AtomicSourceCiTests(unittest.TestCase):
    def workflow(self):
        return yaml.safe_load(WORKFLOW.read_text())

    def test_only_the_assigned_atomic_branch_can_trigger_source_ci(self):
        workflow = self.workflow()
        events = workflow.get("on", workflow.get(True))
        self.assertEqual(set(events), {"push"})
        patterns = events["push"]["branches"]
        for branch, expected in ((BRANCH, True), ("main", False), ("production", False),
                                 ("staging", False), ("atomic/another-task", False),
                                 ("subsection/ob-15-cicd--04-promotion", False)):
            with self.subTest(branch=branch):
                self.assertEqual(any(fnmatch.fnmatchcase(branch, pattern) for pattern in patterns), expected)

    def test_all_jobs_are_read_only_hosted_and_bind_the_exact_source(self):
        workflow = self.workflow()
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        for name, job in workflow["jobs"].items():
            with self.subTest(job=name):
                self.assertEqual(job["runs-on"], "ubuntu-24.04")
                self.assertNotIn("environment", job)
                self.assertNotIn("permissions", job)
                self.assertNotIn("continue-on-error", job)
                checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
                self.assertEqual(checkout["with"]["ref"], "${{ github.sha }}")
                self.assertIs(checkout["with"]["persist-credentials"], False)
                self.assertEqual(checkout["with"]["fetch-depth"], 0)
                for step in job["steps"]:
                    self.assertNotIn("continue-on-error", step)
                    if "uses" in step:
                        self.assertRegex(step["uses"], r"^actions/[a-z-]+@[0-9a-f]{40}$")
        source = WORKFLOW.read_text()
        self.assertNotRegex(source, r"secrets\.|vars\.|id-token|packages:|self-hosted|codestra-deploy|git push|gh api")

    def test_validation_integration_and_security_run_in_order(self):
        jobs = self.workflow()["jobs"]
        self.assertEqual(set(jobs), {"validate", "integration", "security"})
        self.assertNotIn("needs", jobs["validate"])
        self.assertEqual(jobs["integration"]["needs"], "validate")
        self.assertEqual(jobs["security"]["needs"], "integration")
        for name, entrypoint in (("validate", "scripts/validate.sh"),
                                 ("integration", "scripts/integration_test.sh"),
                                 ("security", "scripts/security.sh")):
            job = jobs[name]
            self.assertNotIn("if", job)
            commands = [step["run"] for step in job["steps"] if "run" in step]
            self.assertIn(entrypoint, commands)
            self.assertTrue((ROOT / entrypoint).is_file())
            self.assertFalse(any("|| true" in command for command in commands))

    def test_history_scanner_remains_checksum_verified(self):
        security = self.workflow()["jobs"]["security"]
        commands = [step["run"] for step in security["steps"] if "run" in step]
        self.assertIn("scripts/install_ci_tools.sh gitleaks", commands)
        self.assertLess(commands.index("scripts/install_ci_tools.sh gitleaks"),
                        commands.index("scripts/security.sh"))
        self.assertIs(self.workflow()["concurrency"]["cancel-in-progress"], False)


if __name__ == "__main__":
    unittest.main(verbosity=2)

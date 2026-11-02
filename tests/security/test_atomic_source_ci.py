"""Keep atomic source CI runnable without giving it promotion or runtime authority."""
from __future__ import annotations

import fnmatch
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/atomic-source-ci.yml"
BRANCH = "atomic/ob-15-cicd--04-promotion--pr109-reconcile-20261016"
SOURCE_SHA = "${{ github.event.pull_request.head.sha || github.sha }}"


class AtomicSourceCiTests(unittest.TestCase):
    def workflow(self):
        return yaml.safe_load(WORKFLOW.read_text())

    def test_every_pull_request_and_the_existing_push_lane_trigger_source_ci(self):
        workflow = self.workflow()
        events = workflow.get("on", workflow.get(True))
        self.assertEqual(set(events), {"push", "pull_request"})
        self.assertIsNone(events["pull_request"])
        patterns = events["push"]["branches"]
        for branch, expected in ((BRANCH, True), ("main", False), ("production", False),
                                 ("staging", False), ("atomic/another-task", False),
                                 ("subsection/ob-15-cicd--04-promotion", False)):
            with self.subTest(branch=branch):
                self.assertEqual(any(fnmatch.fnmatchcase(branch, pattern) for pattern in patterns), expected)

    def test_all_jobs_are_read_only_hosted_and_bind_the_exact_source(self):
        workflow = self.workflow()
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(workflow.get("env", {}).get("EXPECTED_SHA"), SOURCE_SHA)
        self.assertEqual(workflow.get("env", {}).get("BASE_SHA"),
                         "${{ github.event.pull_request.base.sha || github.event.before }}")
        for name, job in workflow["jobs"].items():
            with self.subTest(job=name):
                self.assertEqual(job["runs-on"], "ubuntu-24.04")
                self.assertNotIn("environment", job)
                self.assertNotIn("permissions", job)
                self.assertNotIn("continue-on-error", job)
                checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
                self.assertEqual(checkout["with"]["ref"], "${{ env.EXPECTED_SHA }}")
                self.assertNotIn("EXPECTED_SHA", job.get("env", {}))
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
        self.assertEqual(set(jobs), {"validate", "integration", "security", "source-artifacts"})
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



    def test_candidate_artifacts_are_isolated_after_validation_and_always_preserved(self):
        job=self.workflow()["jobs"]["source-artifacts"]
        self.assertEqual(job["needs"],"validate")
        self.assertEqual(job["timeout-minutes"],90)
        self.assertEqual(self.workflow().get("env", {}).get("EXPECTED_SHA"), SOURCE_SHA)
        steps=job["steps"]
        build=next(i for i,s in enumerate(steps) if s.get("run")=="bash scripts/validate_source_artifacts.sh")
        gate=next(i for i,s in enumerate(steps) if "collect_openbao_candidate_evidence.py" in s.get("run",""))
        upload=next(i for i,s in enumerate(steps) if s.get("uses","").startswith("actions/upload-artifact@"))
        self.assertLess(build,gate);self.assertLess(gate,upload)
        self.assertEqual(steps[gate]["if"],"\u0024{{ always() }}")
        self.assertEqual(steps[upload]["if"],"\u0024{{ always() }}")
        self.assertEqual(steps[upload]["with"]["if-no-files-found"],"error")
        self.assertIn('--source-sha "$EXPECTED_SHA"', steps[gate]["run"])
        self.assertEqual(steps[upload]["with"]["name"],
                         "openbao-candidate-${{ env.EXPECTED_SHA }}-${{ github.run_attempt }}")
        setup=next(s for s in steps if s.get("uses","").startswith("actions/setup-go@"))
        self.assertEqual(setup["with"],{"go-version":"1.26.10","cache":False})

    def test_artifact_builder_vendors_before_backport_and_scans_both_before_gate(self):
        script=(ROOT/"scripts/validate_source_artifacts.sh").read_text()
        self.assertIn("scripts/prepare_openbao_test_fixtures.py",script)
        self.assertIn('tail -n 120 "$EVIDENCE_DIR/consumer-tests.log"',script)
        self.assertLess(script.index("cp -a plugins/codestra-jwt-replay"),script.index("go mod vendor"))
        self.assertLess(script.index("go mod vendor"),script.index("scripts/patch_jose_v3_vendor.py"))
        self.assertLess(script.index("scripts/patch_jose_v3_vendor.py"),script.index("go test -count=1"))
        self.assertIn("export GOFLAGS='-mod=vendor -p=2'",script)
        self.assertIn("trivy image --skip-db-update",script)
        self.assertIn("trivy rootfs --skip-db-update",script)
        self.assertNotRegex(script,r"--ignore-unfixed|--severity|docker push|cosign|docker login")
        self.assertNotIn("scripts/build_jti_plugin.sh",script)

    def test_artifact_builder_uses_bash_without_executable_permission(self):
        script = ROOT / "scripts/validate_source_artifacts.sh"
        self.assertEqual(script.stat().st_mode & 0o111, 0)
        commands = [step.get("run") for step in self.workflow()["jobs"]["source-artifacts"]["steps"]]
        self.assertIn("bash scripts/validate_source_artifacts.sh", commands)
        # Execute the real entrypoint without build authority: reaching its first
        # required-input guard proves bash can read it without executable mode.
        result = subprocess.run(["bash", str(script)], cwd=ROOT,
                                env={"PATH": os.environ["PATH"]},
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(result.returncode, 126)
        self.assertIn("EVIDENCE_DIR: set unused bounded evidence directory", result.stderr)


class CommittedSourceValidationTests(unittest.TestCase):
    """Execute the real workflow shell against clean, committed Git fixtures."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Source CI fixture")
        self.git("config", "user.email", "source-ci@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.base = self.commit("clean base\n")
        self.head = self.commit("clean candidate\n")
        self.workflow = yaml.safe_load(WORKFLOW.read_text())

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True).strip()

    def commit(self, content):
        (self.repo / "source.txt").write_text(content)
        self.git("add", "source.txt")
        self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def run_step(self, job, name, **overrides):
        steps = [step["run"] for step in self.workflow["jobs"][job]["steps"]
                 if step.get("name") == name]
        self.assertEqual(len(steps), 1, f"missing workflow step: {name}")
        env = dict(os.environ, EXPECTED_SHA=self.head, BASE_SHA=self.base,
                   GITHUB_SHA=self.base, GITHUB_EVENT_NAME="pull_request")
        env.update(overrides)
        return subprocess.run(["bash", "-euo", "pipefail", "-c", steps[0]],
                              cwd=self.repo, env=env, capture_output=True, text=True)

    def test_all_jobs_accept_exact_pr_head_even_when_merge_sha_differs(self):
        for job in self.workflow["jobs"]:
            with self.subTest(job=job):
                result = self.run_step(job, "Verify exact source")
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_all_jobs_reject_wrong_or_symbolic_source_identity(self):
        for job in self.workflow["jobs"]:
            for target in (self.base, "HEAD", "", "a" * 40):
                with self.subTest(job=job, target=target):
                    result = self.run_step(job, "Verify exact source", EXPECTED_SHA=target,
                                           GITHUB_SHA=self.head)
                    self.assertNotEqual(result.returncode, 0)

    def test_clean_committed_pr_diff_passes(self):
        self.assertEqual(self.git("status", "--porcelain"), "")
        result = self.run_step("validate", "Check committed source diff")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_committed_whitespace_fails_despite_clean_worktree(self):
        self.head = self.commit("committed defect \n")
        self.assertEqual(self.git("status", "--porcelain"), "")
        result = self.run_step("validate", "Check committed source diff")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("trailing whitespace", result.stdout)

    def test_missing_unknown_or_symbolic_pr_base_fails(self):
        for base in ("", "HEAD", "a" * 40, "0" * 40):
            with self.subTest(base=base):
                result = self.run_step("validate", "Check committed source diff", BASE_SHA=base)
                self.assertNotEqual(result.returncode, 0)

    def test_push_checks_the_committed_event_range(self):
        result = self.run_step("validate", "Check committed source diff", GITHUB_EVENT_NAME="push")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.head = self.commit("committed defect \n")
        result = self.run_step("validate", "Check committed source diff", GITHUB_EVENT_NAME="push")
        self.assertNotEqual(result.returncode, 0)

    def test_new_branch_push_checks_against_empty_tree(self):
        result = self.run_step("validate", "Check committed source diff",
                               GITHUB_EVENT_NAME="push", BASE_SHA="0" * 40)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.head = self.commit("committed defect \n")
        result = self.run_step("validate", "Check committed source diff",
                               GITHUB_EVENT_NAME="push", BASE_SHA="0" * 40)
        self.assertNotEqual(result.returncode, 0)

    def test_unexpected_events_fail_closed(self):
        result = self.run_step("validate", "Check committed source diff",
                               GITHUB_EVENT_NAME="pull_request_target")
        self.assertNotEqual(result.returncode, 0)

if __name__ == "__main__":
    unittest.main(verbosity=2)

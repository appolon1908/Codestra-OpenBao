from __future__ import annotations

import importlib.util
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/verify_branch_promotion.py"
SPEC = importlib.util.spec_from_file_location("verify_branch_promotion", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BranchPromotionTests(unittest.TestCase):
    def test_admissible_development_heads(self) -> None:
        for head in (
            "remediation/pas239-fresh-20260924",
            "remediation/openbao-production-completion-v1",
            "sync/openbao-upstream-v2.6.2",
        ):
            self.assertTrue(MODULE.promotion_allowed("development", head), head)
            MODULE.check_event("pull_request", "development", head, "")

    def test_other_heads_cannot_target_development(self) -> None:
        for head in (
            "remediation/",
            "sync/openbao-upstream-",
            "lane-e/openbao-security-closure-20260920",
            "feature/remediation/x",
            "Remediation/x",
            "sync/upstream/v2.6.2",
            "main",
            "test",
            "",
        ):
            self.assertFalse(MODULE.promotion_allowed("development", head), head)
            with self.assertRaisesRegex(SystemExit, "OPENBAO_BRANCH_PROMOTION=FAIL"):
                MODULE.check_event("pull_request", "development", head, "")

    def test_protected_chain_is_the_only_promotion_path(self) -> None:
        chain = ("development", "test", "staging", "production", "main")
        for index, base in enumerate(chain[1:], start=1):
            self.assertTrue(MODULE.promotion_allowed(base, chain[index - 1]))
            for head in chain:
                if head != chain[index - 1]:
                    self.assertFalse(MODULE.promotion_allowed(base, head), f"{head}->{base}")
            self.assertFalse(MODULE.promotion_allowed(base, "remediation/x"))
        self.assertFalse(MODULE.promotion_allowed("feature", "remediation/x"))

    def test_push_only_to_protected_branches(self) -> None:
        for ref in MODULE.PROTECTED:
            MODULE.check_event("push", "", "", ref)
        with self.assertRaisesRegex(SystemExit, "unexpected push branch"):
            MODULE.check_event("push", "", "", "remediation/pas239-fresh-20260924")

    def test_workflow_delegates_to_the_tested_script(self) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/validate.yml").read_text(encoding="utf-8")
        )
        steps = workflow["jobs"]["branch-promotion"]["steps"]
        runs = [step.get("run", "") for step in steps]
        self.assertIn("python3 scripts/verify_branch_promotion.py", runs)
        env = next(step["env"] for step in steps if "env" in step)
        self.assertEqual(
            set(env), {"EVENT_NAME", "BASE_REF", "HEAD_REF", "REF_NAME"}
        )

    def test_require_current_rejects_a_head_missing_development(self) -> None:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False
        )
        if head.returncode != 0:
            self.skipTest("not a git checkout")
        MODULE.require_current("HEAD", "HEAD")
        parent = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", "HEAD~1"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if parent.returncode != 0:
            self.skipTest("shallow checkout without a parent commit")
        with self.assertRaisesRegex(SystemExit, "does not contain"):
            MODULE.require_current(parent.stdout.strip(), "HEAD")


if __name__ == "__main__":
    unittest.main(verbosity=2)

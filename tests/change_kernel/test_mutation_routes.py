"""Every administrative mutation route obeys one cluster lease and one actuator."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github/workflows"
MUTATION_WORKFLOWS = {
    "_deploy-saved-plan.yml": ("apply", "scripts/apply_saved_plan.sh"),
    "runtime-deploy.yml": ("deploy-runtime", "scripts/deploy_runtime.sh"),
    "runtime-rollback.yml": ("rollback", "scripts/rollback.sh"),
    "initialize.yml": ("initialize", "scripts/initialize.sh"),
    "runtime-certification.yml": ("certify", "scripts/rotate-test.sh"),
    "backup-restore-test.yml": ("backup", "scripts/backup.sh"),
    "scheduled-backup.yml": ("backup", "scripts/backup.sh"),
}
# First line that changes OpenBao or the runtime in each script.
FIRST_EFFECT = {
    "scripts/backup.sh": "bao operator raft snapshot save",
    "scripts/deploy_runtime.sh": 'docker stop --time 90 "$container"',
    "scripts/rollback.sh": 'docker stop --time 90 "$current"',
    "scripts/initialize.sh": "bao operator init",
    "scripts/rotate-test.sh": "bao kv put",
    "scripts/revoke-test.sh": '"$revoke_driver" >/dev/null',
    "scripts/apply.sh": '"${kernel[@]}" submit',
}
MUTATION_COMMAND = re.compile(
    r"\bbao\s+(write|delete|policy\s+(write|delete)|secrets\s+(enable|disable|tune|move)|"
    r"auth\s+(enable|disable|tune)|plugin\s+(register|deregister|reload)|kv\s+(put|patch|delete|destroy|undelete)|"
    r"operator\s+(init|rekey|generate-root|raft\s+snapshot\s+restore)|audit\s+(enable|disable)|lease\s+revoke)\b")
# Scripts allowed to contain mutation commands, and why.
ALLOWED_COMMAND_FILES = {
    "scripts/initialize.sh": "custody ceremony, lease-guarded",
    "scripts/rotate-test.sh": "non-production CAS rotation certification, lease-guarded",
    "scripts/restore-test.sh": "isolated restore target only; refuses production and the source cluster",
    "scripts/integration_test.sh": "ephemeral local development container",
    "scripts/integration_test_jti_plugin.sh": "ephemeral local development container",
}


def workflow(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


class WorkflowLockTests(unittest.TestCase):
    def test_every_mutation_workflow_shares_the_non_cancelling_cluster_group(self) -> None:
        for name, (job_name, _) in MUTATION_WORKFLOWS.items():
            document = workflow(name)
            job = document["jobs"][job_name]
            concurrency = job.get("concurrency") or document.get("concurrency")
            with self.subTest(workflow=name):
                self.assertIsInstance(concurrency, dict)
                self.assertRegex(concurrency["group"], r"^openbao-(\$\{\{ inputs\.environment \}\}|production)-mutation$")
                self.assertIs(concurrency["cancel-in-progress"], False)

    def test_every_mutation_workflow_holds_the_durable_lease_around_its_effects(self) -> None:
        for name, (job_name, script) in MUTATION_WORKFLOWS.items():
            job = workflow(name)["jobs"][job_name]
            names = [step.get("name", "") for step in job["steps"]]
            runs = [str(step.get("run", "")) for step in job["steps"]]
            with self.subTest(workflow=name):
                self.assertIn("vars.OPENBAO_CHANGE_KERNEL_DATABASE_URL",
                              job["env"]["OPENBAO_CHANGE_KERNEL_DATABASE_URL"])
                acquire = names.index("Acquire the cluster mutation lease")
                effect = next(i for i, run in enumerate(runs) if script in run or
                              (script == "scripts/apply_saved_plan.sh" and "apply_saved_plan.sh" in run))
                self.assertLess(acquire, effect)
                self.assertIn("lock-acquire", runs[acquire])
                self.assertIn("--ttl 3600", runs[acquire])
                release = job["steps"][-1]
                self.assertEqual(release["name"], "Release the cluster mutation lease")
                self.assertEqual(release["if"], "always()")
                self.assertIn("lock-release", release["run"])

    def test_timeouts_fit_inside_the_lease(self) -> None:
        for name, (job_name, _) in MUTATION_WORKFLOWS.items():
            job = workflow(name)["jobs"][job_name]
            with self.subTest(workflow=name):
                self.assertLessEqual(int(job["timeout-minutes"]), 60)

    def test_read_only_drift_never_takes_the_lease_but_reports_inconsistency(self) -> None:
        drift = workflow("drift-detection.yml")
        self.assertNotIn("lock-acquire", yaml.safe_dump(drift))
        source = (ROOT / "scripts/drift.sh").read_text(encoding="utf-8")
        self.assertIn("lock-status", source)
        self.assertIn("OPENBAO_DRIFT=INCONSISTENT", source)
        self.assertLess(source.index('before="$(mutation_lease_state)"'), source.index("scripts/plan.sh"))
        self.assertLess(source.index("scripts/plan.sh"), source.index('after="$(mutation_lease_state)"'))


class ScriptLeaseTests(unittest.TestCase):
    def test_each_mutation_script_checks_the_lease_immediately_before_its_first_effect(self) -> None:
        for script, effect in FIRST_EFFECT.items():
            source = (ROOT / script).read_text(encoding="utf-8")
            with self.subTest(script=script):
                self.assertIn("require_mutation_lease.sh", source)
                guard = source.index("require_mutation_lease.sh")
                self.assertLess(guard, source.index(effect))
                between = source[guard:source.index(effect)]
                self.assertIsNone(MUTATION_COMMAND.search(between))
                self.assertNotIn("docker stop", source[:guard])

    def test_lease_guard_checks_the_target_cluster_and_fence(self) -> None:
        source = (ROOT / "scripts/require_mutation_lease.sh").read_text(encoding="utf-8")
        for required in ("lock-check", '--environment "$environment"', "OPENBAO_CHANGE_KERNEL_LEASE_FILE",
                         "OPENBAO_CHANGE_KERNEL_DATABASE_URL", "exit 4"):
            self.assertIn(required, source)


class SingleActuatorTests(unittest.TestCase):
    def test_no_other_source_issues_openbao_mutation_commands(self) -> None:
        offenders = []
        for path in sorted((ROOT / "scripts").rglob("*")):
            if not path.is_file() or path.suffix not in {".sh", ".py", ""}:
                continue
            relative = path.relative_to(ROOT).as_posix()
            text = path.read_text(encoding="utf-8", errors="replace")
            if MUTATION_COMMAND.search(text) and relative not in ALLOWED_COMMAND_FILES:
                offenders.append(relative)
        for path in sorted(WORKFLOWS.glob("*.yml")):
            if MUTATION_COMMAND.search(path.read_text(encoding="utf-8")):
                offenders.append(path.relative_to(ROOT).as_posix())
        self.assertEqual(offenders, [])

    def test_lease_guarded_command_files_really_hold_the_lease(self) -> None:
        for relative in ("scripts/initialize.sh", "scripts/rotate-test.sh"):
            with self.subTest(script=relative):
                self.assertIn("require_mutation_lease.sh", (ROOT / relative).read_text(encoding="utf-8"))

    def test_isolated_restore_refuses_production(self) -> None:
        source = (ROOT / "scripts/restore-test.sh").read_text(encoding="utf-8")
        self.assertIn('[[ "$environment" != production ]]', source)
        self.assertIn('"$target_cluster_id" != "$production_cluster_id"', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)

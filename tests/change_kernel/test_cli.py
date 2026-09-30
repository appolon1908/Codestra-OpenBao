from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("build_plan", ROOT / "scripts/build_plan.py")
assert SPEC and SPEC.loader
BUILD_PLAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD_PLAN)


class KernelCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.database = f"sqlite:///{(self.work / 'kernel.db').as_posix()}"

    def cli(self, *arguments: str, lease: str = "lease-a.json") -> subprocess.CompletedProcess[str]:
        env = {**os.environ, "OPENBAO_CHANGE_KERNEL_LEASE_FILE": str(self.work / lease),
               "PYTHONDONTWRITEBYTECODE": "1"}
        return subprocess.run([sys.executable, "-m", "codestra.change_kernel.cli", "--database", self.database,
                               *arguments], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)

    def acquire(self, holder: str, lease: str) -> subprocess.CompletedProcess[str]:
        return self.cli("lock-acquire", "--environment", "staging", "--holder", holder,
                        "--purpose", "runtime-deploy", "--run-ref", f"run-{holder}", "--ttl", "600", lease=lease)

    def test_second_workflow_is_refused_while_first_holds_the_cluster_lock(self) -> None:
        first = self.acquire("deploy", "lease-a.json")
        self.assertEqual(first.returncode, 0, first.stderr)
        lease = json.loads((self.work / "lease-a.json").read_text())
        self.assertEqual(lease["exclusionKey"], "openbao:staging:codestra-bao-staging-01")
        self.assertEqual(stat_mode(self.work / "lease-a.json") & 0o077 if os.name != "nt" else 0, 0)

        second = self.acquire("restore", "lease-b.json")
        self.assertEqual(second.returncode, 3)
        self.assertIn("ENVIRONMENT_LOCK_HELD", second.stderr)
        self.assertFalse((self.work / "lease-b.json").exists())

        self.assertEqual(self.cli("lock-check").returncode, 0)
        self.assertEqual(self.cli("lock-release").returncode, 0)
        self.assertEqual(self.cli("lock-check").returncode, 2)
        self.assertEqual(self.acquire("restore", "lease-b.json").returncode, 0)

    def test_released_or_superseded_lease_fails_the_fence_check(self) -> None:
        self.assertEqual(self.acquire("deploy", "lease-a.json").returncode, 0)
        stale = (self.work / "lease-a.json").read_text()
        self.assertEqual(self.acquire("deploy", "lease-a.json").returncode, 0)
        (self.work / "stale.json").write_text(stale)
        result = self.cli("lock-check", lease="stale.json")
        self.assertEqual(result.returncode, 4)
        self.assertIn("LEASE_FENCE_DENIED", result.stderr)

    def test_submit_refuses_a_checksum_file_naming_another_plan(self) -> None:
        live = self.work / "live"
        (live / "policies").mkdir(parents=True)
        (live / "jwt-roles").mkdir()
        for name, value in {"mounts.json": {}, "auth.json": {}, "audit.json": {"file-audit/": {"type": "file"}},
                            "policies.json": [], "jwt-config.json": {}, "jwt-roles.json": [],
                            "plugin-info.json": {}, "codestra-config.json": {}}.items():
            (live / name).write_text(json.dumps(value))
        plan = BUILD_PLAN.build("staging", live, "c" * 40)
        plan["warnings"] = [item for item in plan["warnings"] if "file-audit" not in item]
        plan_file = self.work / "plan.json"
        plan_file.write_text(json.dumps(plan))
        decoy = self.work / "good.json"
        decoy.write_text("{}")
        checksum = self.work / "plan.json.sha256"
        checksum.write_text(f"{hashlib.sha256(decoy.read_bytes()).hexdigest()}  good.json\n")
        common = ("submit", "--environment", "staging", "--tenant", "platform", "--idempotency-key", "k1",
                  "--request-id", "r1", "--correlation-id", "c1", "--plan", str(plan_file),
                  "--checksum", str(checksum), "--live-dir", str(live), "--subject", "operator")
        refused = self.cli(*common)
        self.assertEqual(refused.returncode, 2)
        self.assertIn("PLAN_CHECKSUM_NAMES_OTHER_FILE", refused.stderr)

        checksum.write_text(f"{hashlib.sha256(plan_file.read_bytes()).hexdigest()}  plan.json\n")
        accepted = self.cli(*common)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        change = json.loads(accepted.stdout)
        self.assertEqual(change["status"], "AWAITING_APPROVAL")
        status = json.loads(self.cli("status", "--change-id", change["change_id"]).stdout)
        self.assertEqual(status["exclusion_key"], "openbao:staging:codestra-bao-staging-01")
        self.assertNotIn("payload", json.dumps(status))


def stat_mode(path: Path) -> int:
    return path.stat().st_mode


if __name__ == "__main__":
    unittest.main(verbosity=2)

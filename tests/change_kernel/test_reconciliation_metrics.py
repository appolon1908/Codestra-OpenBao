from __future__ import annotations

import datetime as dt
import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from codestra.change_kernel import metrics, reconciliation  # noqa: E402
from codestra.change_kernel.authority import Authority  # noqa: E402
from codestra.change_kernel.kernel import ChangeKernel, KernelError, Principal  # noqa: E402
from codestra.change_kernel.store import Store  # noqa: E402

SPEC = importlib.util.spec_from_file_location("build_plan", ROOT / "scripts/build_plan.py")
assert SPEC and SPEC.loader
BUILD_PLAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD_PLAN)
NOW = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.timezone.utc)


def live_dir(**overrides) -> Path:
    directory = Path(tempfile.mkdtemp())
    (directory / "policies").mkdir()
    (directory / "jwt-roles").mkdir()
    values = {"mounts.json": {}, "auth.json": {}, "audit.json": {"file-audit/": {"type": "file"}},
              "policies.json": [], "jwt-config.json": {}, "jwt-roles.json": [],
              "plugin-info.json": {}, "codestra-config.json": {}}
    values.update(overrides)
    for name, value in values.items():
        (directory / name).write_text(json.dumps(value), encoding="utf-8")
    return directory


class ReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = Store("sqlite::memory:")
        self.store.migrate()
        self.kernel = ChangeKernel(self.store, Authority(), lambda: NOW)
        self.engines = json.loads((ROOT / "config/secrets/engines.v1.json").read_text(encoding="utf-8"))

    def test_every_drift_class_is_produced_from_real_plan_output(self) -> None:
        live = live_dir(**{"audit.json": {},
                           "mounts.json": {"codestra/": {"type": "database"}, "database/": {"type": "database"}},
                           "jwt-roles.json": ["intruder-development"]})
        plan = BUILD_PLAN.build("development", live, "a" * 40)
        findings = reconciliation.classify(plan, live, self.engines)
        classes = {item["classification"] for item in findings}
        self.assertTrue({"MISSING", "SECURITY_CRITICAL", "CONFLICT", "DISABLED"} <= classes, classes)
        auth = [item for item in findings if item["resource_kind"] == "auth_method"]
        self.assertTrue(auth and all(item["severity"] == "critical" for item in auth))

        live = live_dir(**{"auth.json": {"jwt-codestra/": {
            "type": "codestra-jwt-replay", "plugin_version": "v1.1.0", "running_plugin_version": "v1.1.0",
            "running_sha256": json.loads((ROOT / "plugins/codestra-jwt-replay/plugin.v1.json").read_text())["binarySha256"]}},
            "jwt-roles.json": ["intruder-development"]})
        plan = BUILD_PLAN.build("development", live, "a" * 40)
        self.assertIn("UNMANAGED", {item["classification"] for item in reconciliation.classify(plan, live, self.engines)})

    def test_run_is_recorded_and_never_creates_a_change(self) -> None:
        live = live_dir()
        plan = BUILD_PLAN.build("development", live, "a" * 40)
        result = reconciliation.record_run(self.kernel, environment="development", plan=plan, live_dir=live,
                                           lease_state_before="FREE", lease_state_after="FREE")
        self.assertEqual(result["status"], "DRIFT_DETECTED")
        self.assertGreater(result["findings"], 0)
        self.assertEqual(self.store.one("SELECT COUNT(*) AS n FROM drift_findings")["n"], result["findings"])
        self.assertEqual(self.store.one("SELECT COUNT(*) AS n FROM change_requests")["n"], 0)
        self.assertEqual(self.store.one("SELECT COUNT(*) AS n FROM outbox")["n"], 0)

    def test_observation_during_a_held_lease_is_inconsistent_not_clean(self) -> None:
        live = live_dir()
        plan = {"environment": "development", "planSourceSha": "a" * 40, "operations": [], "warnings": []}
        result = reconciliation.record_run(self.kernel, environment="development", plan=plan, live_dir=live,
                                           lease_state_before="FREE", lease_state_after="HELD:runtime-deploy")
        self.assertEqual(result["status"], "INCONSISTENT")
        self.assertEqual(result["findings"], 0)
        clean = reconciliation.record_run(self.kernel, environment="development", plan=plan, live_dir=live,
                                          lease_state_before="FREE", lease_state_after="FREE")
        self.assertEqual(clean["status"], "IN_SYNC")

    def test_plan_for_another_environment_is_refused(self) -> None:
        plan = {"environment": "staging", "operations": [], "warnings": []}
        with self.assertRaises(ValueError):
            reconciliation.record_run(self.kernel, environment="development", plan=plan, live_dir=live_dir(),
                                      lease_state_before="FREE", lease_state_after="FREE")


class MetricsTests(unittest.TestCase):
    def test_metric_family_is_bounded_and_secret_free(self) -> None:
        store = Store("sqlite::memory:")
        store.migrate()
        kernel = ChangeKernel(store, Authority(), lambda: NOW)
        principal = Principal("operator", frozenset({"platform"}), frozenset({"development"}),
                              frozenset({"change.submit"}))
        plan = BUILD_PLAN.build("development", live_dir(), "a" * 40)
        plan["warnings"] = []
        kernel.submit(principal, tenant_id="platform", environment="development", idempotency_key="k",
                      request_id="r", correlation_id="c", plan=plan, resource_fingerprint="f")
        kernel.record_denial(KernelError("TENANT_OR_ENVIRONMENT_NOT_AUTHORIZED", 403), "operator", "development")
        kernel.record_denial(KernelError("PLAN_STALE_AUTHORITY_CHANGED", 409), "operator", "development")
        kernel.acquire_lock("development", holder="deploy", purpose="runtime-deploy", run_ref="r1")
        live = live_dir()
        reconciliation.record_run(kernel, environment="development", plan=plan, live_dir=live,
                                  lease_state_before="FREE", lease_state_after="FREE")
        work = Path(tempfile.mkdtemp())
        backup = work / "backup.json"
        backup.write_text(json.dumps({"backup": "PASS", "completedAt": "2026-09-30T11:00:00Z"}))
        restore = work / "restore.json"
        restore.write_text(json.dumps({"restore": "PASS", "rtoMet": True}))
        text = metrics.render(kernel, "development", backup_evidence=backup, restore_evidence=restore,
                              cluster_status={"voters": 1, "sealed": None})
        for name in ("openbao_v3_changes_total", "openbao_v3_change_failures_total",
                     "openbao_v3_policy_denials_total", "openbao_v3_safety_denials_total",
                     "openbao_v3_reconciliation_total", "openbao_v3_drift_total", "openbao_v3_outbox_pending",
                     "openbao_v3_worker_leases", "openbao_v3_backup_age_seconds",
                     "openbao_v3_restore_last_success", "openbao_v3_cluster_voters", "openbao_v3_cluster_sealed"):
            self.assertIn(f"# TYPE {name} ", text)
        self.assertIn('openbao_v3_policy_denials_total{environment="development"} 1', text)
        self.assertIn('openbao_v3_safety_denials_total{environment="development"} 1', text)
        self.assertIn('openbao_v3_worker_leases{environment="development"} 1', text)
        self.assertIn('openbao_v3_backup_age_seconds{environment="development"} 3600', text)
        self.assertIn('openbao_v3_cluster_sealed{environment="development"} 1', text)
        labels = set(re.findall(r"([a-z_]+)=\"", text))
        self.assertLessEqual(labels, set(metrics.ALLOWED_LABELS))
        for forbidden in ("path \"", "cel_program", "codestra/data", "operator\""):
            self.assertNotIn(forbidden, text)

    def test_unbounded_label_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            metrics._line("openbao_v3_changes_total", 1, {"path": "codestra/data/x"})


if __name__ == "__main__":
    unittest.main(verbosity=2)

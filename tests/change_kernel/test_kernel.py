from __future__ import annotations

import datetime as dt
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
import sys  # noqa: E402

sys.path.insert(0, str(ROOT))
from codestra.change_kernel import actuator  # noqa: E402
from codestra.change_kernel.authority import Authority, AuthorityError  # noqa: E402
from codestra.change_kernel.canonical import SecretMaterialError, assert_secret_free  # noqa: E402
from codestra.change_kernel.kernel import ChangeKernel, KernelError, Lease, Principal  # noqa: E402
from codestra.change_kernel.store import Store, StoreError  # noqa: E402

SPEC = importlib.util.spec_from_file_location("build_plan", ROOT / "scripts/build_plan.py")
assert SPEC and SPEC.loader
BUILD_PLAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD_PLAN)

SOURCE_SHA = "a" * 40
SUBMITTER = Principal("platform-operator", frozenset({"platform"}), frozenset({"development", "staging"}),
                      frozenset({"change.submit", "change.execute"}))
APPROVER = "kazan555"


class AuthorizedAuthority(Authority):
    """Real authority files, with the runtime gate opened only inside this test."""

    authorized = True

    def production_gate(self, name):
        gate = super().production_gate(name)
        gate["runtimeApplyAuthorized"] = self.authorized
        return gate


class Clock:
    def __init__(self) -> None:
        self.now = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += dt.timedelta(seconds=seconds)


class FakeOpenBao:
    """Records calls; state flips to 'applied' only when a call is made."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.applied: set[str] = set()
        self.raise_on: set[str] = set()
        self.exit_code = 0
        self.apply_effect = True

    def runner(self, argv, timeout):
        self.calls.append(argv)
        name = self._name(argv)
        if name in self.raise_on:
            self.applied.add(name)
            raise subprocess.TimeoutExpired(argv, timeout)
        if self.apply_effect:
            self.applied.add(name)
        return self.exit_code

    def readback(self, operation):
        return operation["name"] in self.applied

    @staticmethod
    def _name(argv):
        if argv[1:3] == ["plugin", "register"]:
            return argv[-1]
        if argv[1:3] == ["secrets", "enable"]:
            return argv[3].split("=", 1)[1] + "/"
        if argv[1:3] == ["auth", "enable"]:
            return argv[3].split("=", 1)[1] + "/"
        return argv[3] if argv[1:3] == ["policy", "write"] else argv[2]


def empty_live_dir() -> Path:
    directory = Path(tempfile.mkdtemp())
    (directory / "policies").mkdir()
    (directory / "jwt-roles").mkdir()
    for name, value in {"mounts.json": {}, "auth.json": {}, "audit.json": {"file-audit/": {"type": "file"}},
                        "policies.json": [], "jwt-config.json": {}, "jwt-roles.json": [],
                        "plugin-info.json": {}, "codestra-config.json": {}}.items():
        (directory / name).write_text(json.dumps(value), encoding="utf-8")
    return directory


def audit_ok(plan):
    plan["warnings"] = [item for item in plan["warnings"] if "file-audit" not in item]
    return plan


class KernelTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.store = Store("sqlite::memory:")
        self.store.migrate()
        self.authority = AuthorizedAuthority()
        self.kernel = ChangeKernel(self.store, self.authority, self.clock)
        self.plan = audit_ok(BUILD_PLAN.build("development", empty_live_dir(), SOURCE_SHA))
        self.bao = FakeOpenBao()

    def submit(self, key="idem-1", plan=None, principal=SUBMITTER, environment="development",
               tenant="platform", fingerprint="fp-1"):
        return self.kernel.submit(principal, tenant_id=tenant, environment=environment, idempotency_key=key,
                                  request_id="req-1", correlation_id="corr-1", plan=plan or self.plan,
                                  resource_fingerprint=fingerprint)

    def approved(self, **kwargs):
        change = self.submit(**kwargs)
        self.kernel.approve(change["change_id"], approver=APPROVER, plan_digest=change["plan_digest"],
                            environment=change["environment"], evidence_ref="gh-run-1", valid_seconds=900)
        return change

    def lease(self, holder="worker-a", environment="development", ttl=600):
        return self.kernel.acquire_lock(environment, holder=holder, purpose="saved-plan-apply",
                                        run_ref="run-1", ttl_seconds=ttl)

    def run_actuator(self, change, lease, fingerprint="fp-1"):
        return actuator.execute(self.kernel, change["change_id"], lease, SUBMITTER, fingerprint,
                                runner=self.bao.runner, readback=self.bao.readback)

    def status(self, change):
        return self.store.one("SELECT status FROM change_requests WHERE change_id = ?",
                              (change["change_id"],))["status"]


class SubmissionTests(KernelTestCase):
    def test_policy_and_auth_plan_awaits_approval_and_persists_outbox(self) -> None:
        change = self.submit()
        self.assertEqual(change["status"], "AWAITING_APPROVAL")
        self.assertEqual(change["exclusion_key"], "openbao:development:codestra-bao-development-01")
        self.assertEqual(self.store.one("SELECT COUNT(*) AS n FROM outbox")["n"], 1)
        self.assertGreater(self.store.one("SELECT COUNT(*) AS n FROM operations")["n"], 0)

    def test_same_key_same_payload_returns_same_change(self) -> None:
        first = self.submit()
        second = self.submit()
        self.assertEqual(first["change_id"], second["change_id"])
        self.assertEqual(self.store.one("SELECT COUNT(*) AS n FROM change_requests")["n"], 1)

    def test_same_key_different_plan_is_idempotency_conflict(self) -> None:
        self.submit()
        other = BUILD_PLAN.build("development", empty_live_dir(), "b" * 40)
        with self.assertRaises(KernelError) as caught:
            self.submit(plan=audit_ok(other))
        self.assertEqual((caught.exception.code, caught.exception.status), ("IDEMPOTENCY_CONFLICT", 409))
        with self.assertRaises(KernelError) as caught:
            self.submit(fingerprint="fp-2")
        self.assertEqual(caught.exception.code, "IDEMPOTENCY_CONFLICT")

    def test_idempotency_is_tenant_scoped(self) -> None:
        both = Principal("op", frozenset({"platform", "beyvra"}), frozenset({"development"}),
                         frozenset({"change.submit"}))
        a = self.submit(principal=both, tenant="platform")
        b = self.submit(principal=both, tenant="beyvra")
        self.assertNotEqual(a["change_id"], b["change_id"])

    def test_tenant_and_environment_come_from_principal_not_request(self) -> None:
        with self.assertRaises(KernelError) as caught:
            self.submit(tenant="beyvra")
        self.assertEqual(caught.exception.status, 403)
        with self.assertRaises(KernelError) as caught:
            self.submit(environment="production", plan=self.plan)
        self.assertEqual(caught.exception.status, 403)

    def test_plan_for_another_environment_is_refused(self) -> None:
        staging = audit_ok(BUILD_PLAN.build("staging", empty_live_dir(), SOURCE_SHA))
        with self.assertRaises(KernelError) as caught:
            self.submit(plan=staging, environment="development")
        self.assertEqual(caught.exception.code, "PLAN_ENVIRONMENT_MISMATCH")

    def test_destroy_warnings_and_unknown_kinds_are_refused(self) -> None:
        for mutate, code in (
            (lambda p: p["counts"].__setitem__("destroy", 1), "PLAN_CONTAINS_DESTROY"),
            (lambda p: p["warnings"].append("drift"), "PLAN_HAS_WARNINGS"),
            (lambda p: p["operations"][0].__setitem__("action", "delete"), "PLAN_OPERATION_REFUSED"),
            (lambda p: p["operations"][0].__setitem__("kind", "audit_device"), "PLAN_OPERATION_REFUSED"),
        ):
            plan = json.loads(json.dumps(self.plan))
            mutate(plan)
            with self.subTest(code=code), self.assertRaises(KernelError) as caught:
                self.submit(plan=plan, key=code)
            self.assertEqual(caught.exception.code, code)

    def test_secret_shaped_payload_never_reaches_storage(self) -> None:
        plan = json.loads(json.dumps(self.plan))
        plan["operations"][0]["payload"]["note"] = "".join(("hv", "s", ".", "A" * 30))
        with self.assertRaises(SecretMaterialError) as caught:
            self.submit(plan=plan)
        self.assertNotIn("AAAA", str(caught.exception))
        self.assertEqual(self.store.one("SELECT COUNT(*) AS n FROM change_requests")["n"], 0)
        with self.assertRaises(SecretMaterialError):
            assert_secret_free({"client_" + "secret": "x"})


class ApprovalTests(KernelTestCase):
    def test_only_the_required_independent_approver_binds_the_exact_plan(self) -> None:
        change = self.submit()
        cases = (
            ({"approver": "someone"}, "APPROVER_NOT_AUTHORIZED"),
            ({"plan_digest": "0" * 64}, "APPROVAL_PLAN_DIGEST_MISMATCH"),
            ({"environment": "staging"}, "APPROVAL_ENVIRONMENT_MISMATCH"),
            ({"valid_seconds": 10 ** 6}, "APPROVAL_VALIDITY_OUT_OF_RANGE"),
        )
        for override, code in cases:
            arguments = {"approver": APPROVER, "plan_digest": change["plan_digest"],
                         "environment": "development", "evidence_ref": "gh-run-1", "valid_seconds": 900}
            arguments.update(override)
            with self.subTest(code=code), self.assertRaises(KernelError) as caught:
                self.kernel.approve(change["change_id"], **arguments)
            self.assertEqual(caught.exception.code, code)

    def test_submitter_cannot_approve_own_change(self) -> None:
        own = Principal(APPROVER, frozenset({"platform"}), frozenset({"development"}), frozenset({"change.submit"}))
        change = self.submit(principal=own)
        with self.assertRaises(KernelError) as caught:
            self.kernel.approve(change["change_id"], approver=APPROVER, plan_digest=change["plan_digest"],
                                environment="development", evidence_ref="gh-run-1", valid_seconds=900)
        self.assertEqual(caught.exception.code, "APPROVER_NOT_INDEPENDENT")

    def test_unapproved_or_expired_approval_cannot_execute(self) -> None:
        change = self.submit()
        lease = self.lease()
        with self.assertRaises(KernelError) as caught:
            self.run_actuator(change, lease)
        self.assertEqual(caught.exception.code, "CHANGE_NOT_EXECUTABLE")
        self.kernel.approve(change["change_id"], approver=APPROVER, plan_digest=change["plan_digest"],
                            environment="development", evidence_ref="gh-run-1", valid_seconds=60)
        self.clock.advance(61)
        with self.assertRaises(KernelError) as caught:
            self.run_actuator(change, lease)
        self.assertEqual(caught.exception.code, "APPROVAL_EXPIRED")
        self.assertEqual(self.bao.calls, [])


class LockTests(KernelTestCase):
    def test_second_writer_on_same_cluster_is_refused(self) -> None:
        self.kernel.acquire_lock("development", holder="deploy-run", purpose="runtime-deploy", run_ref="r1")
        with self.assertRaises(KernelError) as caught:
            self.kernel.acquire_lock("development", holder="restore-run", purpose="restore", run_ref="r2")
        self.assertEqual((caught.exception.code, caught.exception.status), ("ENVIRONMENT_LOCK_HELD", 423))

    def test_scheduled_backup_blocks_concurrent_restore_and_other_clusters_are_independent(self) -> None:
        self.kernel.acquire_lock("staging", holder="scheduled-backup", purpose="backup", run_ref="r1")
        with self.assertRaises(KernelError):
            self.kernel.acquire_lock("staging", holder="restore", purpose="restore", run_ref="r2")
        self.kernel.acquire_lock("development", holder="restore", purpose="restore", run_ref="r3")

    def test_environment_spelling_cannot_create_a_second_lock(self) -> None:
        for alias in ("Development", "dev", "development ", "../development"):
            with self.subTest(alias=alias), self.assertRaises(AuthorityError):
                self.authority.exclusion_key(alias)

    def test_only_current_holder_releases_and_expiry_fences_out_stale_holder(self) -> None:
        stale = self.lease("worker-a", ttl=60)
        with self.assertRaises(KernelError) as caught:
            self.kernel.release_lock(Lease(stale.exclusion_key, "worker-b", stale.fence_token, stale.expires_at))
        self.assertEqual(caught.exception.code, "NOT_LOCK_HOLDER")
        self.clock.advance(61)
        fresh = self.lease("worker-b")
        self.assertGreater(fresh.fence_token, stale.fence_token)
        with self.assertRaises(KernelError) as caught:
            self.kernel.check_fence(stale)
        self.assertEqual(caught.exception.code, "LEASE_FENCE_DENIED")
        with self.assertRaises(KernelError):
            self.kernel.release_lock(stale)
        self.kernel.release_lock(fresh)
        self.assertIsNone(self.kernel.lock_status("development"))

    def test_reacquire_by_same_holder_invalidates_its_older_token(self) -> None:
        first = self.lease("worker-a")
        second = self.lease("worker-a")
        with self.assertRaises(KernelError):
            self.kernel.check_fence(first)
        self.kernel.check_fence(second)


class ExecutionTests(KernelTestCase):
    def test_approved_change_executes_and_reads_back_every_operation(self) -> None:
        change = self.approved()
        result = self.run_actuator(change, self.lease())
        self.assertEqual(result, "SUCCEEDED")
        operations = self.store.one("SELECT COUNT(*) AS n FROM operations")["n"]
        self.assertEqual(len(self.bao.calls), operations)
        self.assertEqual(self.bao.calls[0][1:3], ["plugin", "register"])
        statuses = {row["status"] for row in self.store.all("SELECT status FROM operations")}
        self.assertEqual(statuses, {"CONFIRMED"})

    def test_runtime_gate_closed_means_no_effect(self) -> None:
        change = self.approved()
        self.authority.authorized = False
        with self.assertRaises(KernelError) as caught:
            self.run_actuator(change, self.lease())
        self.assertIn(caught.exception.code, {"PRODUCTION_GATE_CHANGED", "RUNTIME_APPLY_NOT_AUTHORIZED"})
        self.assertEqual(self.bao.calls, [])

    def test_wrong_cluster_lease_and_changed_fingerprint_are_refused(self) -> None:
        change = self.approved()
        with self.assertRaises(KernelError) as caught:
            self.run_actuator(change, self.lease(environment="staging"))
        self.assertEqual(caught.exception.code, "LEASE_WRONG_TARGET")
        with self.assertRaises(KernelError) as caught:
            self.run_actuator(change, self.lease(), fingerprint="fp-other")
        self.assertEqual(caught.exception.code, "RESOURCE_FINGERPRINT_CHANGED")
        self.assertEqual(self.bao.calls, [])

    def test_tampered_stored_plan_is_refused(self) -> None:
        change = self.approved()
        plan = json.loads(self.store.one("SELECT plan_json FROM plans")["plan_json"])
        plan["operations"][0]["payload"]["version"] = "v9.9.9"
        self.store.execute("UPDATE plans SET plan_json = ?", (json.dumps(plan),))
        with self.assertRaises(KernelError) as caught:
            self.run_actuator(change, self.lease())
        self.assertEqual(caught.exception.code, "PLAN_DIGEST_CHANGED")
        self.assertEqual(self.bao.calls, [])

    def test_stale_authority_is_refused(self) -> None:
        plan = json.loads(json.dumps(self.plan))
        first = next(iter(plan["authorityChecksums"]))
        plan["authorityChecksums"][first] = "0" * 64
        change = self.approved(plan=plan)
        with self.assertRaises(KernelError) as caught:
            self.run_actuator(change, self.lease())
        self.assertEqual(caught.exception.code, "PLAN_STALE_AUTHORITY_CHANGED")

    def test_lease_lost_mid_change_stops_before_next_call(self) -> None:
        change = self.approved()
        lease = self.lease(ttl=60)
        kernel, clock = self.kernel, self.clock

        def expire_after_first(argv, timeout):
            code = self.bao.runner(argv, timeout)
            clock.advance(61)
            kernel.acquire_lock("development", holder="restore-run", purpose="restore", run_ref="r9")
            return code

        with self.assertRaises(KernelError) as caught:
            actuator.execute(kernel, change["change_id"], lease, SUBMITTER, "fp-1",
                             runner=expire_after_first, readback=self.bao.readback)
        self.assertEqual(caught.exception.code, "LEASE_FENCE_DENIED")
        self.assertEqual(len(self.bao.calls), 1)

    def test_crash_after_acceptance_is_unknown_and_never_blindly_replayed(self) -> None:
        change = self.approved()
        self.bao.raise_on.add("codestra-jwt-replay")
        result = self.run_actuator(change, self.lease())
        self.assertEqual(result, "RECONCILIATION_REQUIRED")
        calls_before = len(self.bao.calls)
        with self.assertRaises(KernelError) as caught:
            self.run_actuator(change, self.lease())
        self.assertEqual(caught.exception.code, "CHANGE_NOT_EXECUTABLE")
        state = actuator.reconcile(self.kernel, change["change_id"], self.lease(), "readback-run-2",
                                   readback=self.bao.readback)
        self.assertEqual(state, "RETRY")
        self.assertEqual(len(self.bao.calls), calls_before)
        self.bao.raise_on.clear()
        self.assertEqual(self.run_actuator(change, self.lease()), "SUCCEEDED")
        self.assertEqual(sum(1 for call in self.bao.calls if call[1:3] == ["plugin", "register"]), 1)

    def test_accepted_call_without_matching_readback_is_not_marked_applied(self) -> None:
        change = self.approved()
        self.bao.apply_effect = False
        self.assertEqual(self.run_actuator(change, self.lease()), "RECONCILIATION_REQUIRED")
        self.assertEqual(len(self.bao.calls), 1)
        self.assertNotIn("CONFIRMED", {row["status"] for row in self.store.all("SELECT status FROM operations")})

    def test_failed_call_retries_then_dead_letters(self) -> None:
        change = self.approved()
        self.bao.apply_effect, self.bao.exit_code = False, 2
        results = [self.run_actuator(change, self.lease()) for _ in range(3)]
        self.assertEqual(results, ["RETRY", "RETRY", "DEAD_LETTER"])
        with self.assertRaises(KernelError):
            self.run_actuator(change, self.lease())

    def test_process_death_is_recovered_by_the_next_holder_as_unknown(self) -> None:
        change = self.approved()
        stale = self.lease(ttl=60)
        attempt = self.kernel.begin_attempt(change["change_id"], stale, SUBMITTER, "fp-1")
        self.kernel.intend(attempt, attempt.operations[0]["operation_id"], stale)
        self.clock.advance(61)
        fresh = self.lease("worker-b")
        self.assertEqual(self.kernel.recover_interrupted(change["change_id"], fresh), "RECONCILIATION_REQUIRED")
        with self.assertRaises(KernelError):
            self.kernel.recover_interrupted(change["change_id"], fresh)
        state = actuator.reconcile(self.kernel, change["change_id"], fresh, "readback-run-3",
                                   readback=self.bao.readback)
        self.assertEqual(state, "RETRY")

    def test_every_transition_is_audited_without_payloads(self) -> None:
        change = self.approved()
        self.run_actuator(change, self.lease())
        types = [row["event_type"] for row in self.store.all("SELECT event_type FROM events ORDER BY occurred_at")]
        for expected in ("CHANGE_SUBMITTED", "CHANGE_APPROVED", "LOCK_ACQUIRED", "ATTEMPT_STARTED",
                         "DISPATCH_INTENDED", "DISPATCH_CONFIRMED", "CHANGE_SUCCEEDED"):
            self.assertIn(expected, types)
        stored = json.dumps(self.store.all("SELECT payload_json FROM events"))
        stored += json.dumps(self.store.all("SELECT payload_json FROM outbox"))
        self.assertNotIn("cel_program", stored)
        self.assertNotIn("capabilities", stored)


class ClassificationTests(unittest.TestCase):
    def test_native_operations_are_classified_by_semantics_not_method(self) -> None:
        authority = Authority()
        contract = json.loads((ROOT / "codestra/api/service-contract.v1.json").read_text(encoding="utf-8"))
        results = {op["id"]: authority.native_operation(op) for op in contract["nativeApi"]["operations"]}
        self.assertEqual(results["database-creds"], ("SECRET_ENGINE", True))
        self.assertEqual(results["kv-read"], ("READ_ONLY", True))
        self.assertEqual(results["pki-issue"][0], "PKI")
        self.assertEqual(results["init"][0], "CUSTODY")
        self.assertEqual(results["unseal"][0], "CUSTODY")
        self.assertEqual(results["raft-snapshot-restore"][0], "DESTRUCTIVE")
        self.assertEqual(results["raft-snapshot"], ("CLUSTER", True))
        self.assertEqual(results["health"], ("READ_ONLY", False))
        self.assertTrue(all(risk in authority.classes for risk, _ in results.values()))

    def test_production_changes_carry_the_production_overlay(self) -> None:
        authority = Authority()
        self.assertEqual(authority.effective_class(["POLICY", "AUTH"], "production"), "PRODUCTION")
        self.assertEqual(authority.effective_class(["POLICY"], "staging"), "POLICY")

    def test_repository_gate_is_closed_today(self) -> None:
        self.assertFalse(Authority().production_gate("production")["runtimeApplyAuthorized"])


class StoreTests(unittest.TestCase):
    def test_changed_applied_migration_is_refused(self) -> None:
        store = Store("sqlite::memory:")
        store.migrate()
        store.execute("UPDATE schema_migrations SET checksum = 'x'")
        with self.assertRaises(StoreError):
            store.migrate()

    def test_destroy_rows_are_rejected_by_schema(self) -> None:
        store = Store("sqlite::memory:")
        store.migrate()
        with self.assertRaises(Exception):
            store.execute("INSERT INTO plans VALUES ('p','c','d','development','s','a','f',0,0,1,'{}','t')")


if __name__ == "__main__":
    unittest.main(verbosity=2)

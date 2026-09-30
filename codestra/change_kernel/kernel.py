"""The change kernel: one durable path from reviewed plan to fenced, read-back execution.

Every state transition is one database transaction. Nothing here contacts
OpenBao; the actuator performs calls only between a persisted dispatch intent
and its recorded resolution.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from .authority import Authority, AuthorityError
from .canonical import assert_secret_free, canonical_json, digest
from .store import Store

UNRESOLVED_INTENTS = ("INTENDED", "UNKNOWN")
EXECUTABLE_STATUSES = ("COMMITTED", "RETRY")
DEFAULT_MAX_ATTEMPTS = 3


class KernelError(Exception):
    """A refused request. `code` is stable; `status` is the HTTP status an API returns."""

    def __init__(self, code: str, status: int = 422, detail: str = "") -> None:
        super().__init__(f"{code}{': ' + detail if detail else ''}")
        self.code = code
        self.status = status
        self.detail = detail


@dataclass(frozen=True)
class Principal:
    """An identity already bound from validated credentials, never from request headers."""

    subject: str
    tenants: frozenset[str]
    environments: frozenset[str]
    roles: frozenset[str] = field(default_factory=frozenset)

    def authorization_digest(self, tenant_id: str, environment: str) -> str:
        return digest({
            "subject": self.subject,
            "tenant": tenant_id,
            "environment": environment,
            "roles": sorted(self.roles),
        })


@dataclass(frozen=True)
class Lease:
    exclusion_key: str
    holder: str
    fence_token: int
    expires_at: str


@dataclass(frozen=True)
class Attempt:
    attempt_id: str
    change_id: str
    number: int
    fence_token: int
    operations: tuple[dict[str, Any], ...]


def utc(now: dt.datetime) -> str:
    return now.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_utc(value: str) -> dt.datetime:
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


class ChangeKernel:
    def __init__(self, store: Store, authority: Authority,
                 clock: Callable[[], dt.datetime] | None = None) -> None:
        self.store = store
        self.authority = authority
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))

    # --- helpers ---------------------------------------------------------------------

    def _now(self) -> dt.datetime:
        return self.clock().astimezone(dt.timezone.utc)

    def _event(self, event_type: str, change: dict[str, Any] | None, actor: str,
               payload: dict[str, Any], now: dt.datetime, *, tenant_id: str = "platform",
               request_id: str = "", correlation_id: str = "") -> None:
        assert_secret_free(payload)
        self.store.execute(
            "INSERT INTO events (event_id, change_id, event_type, occurred_at, request_id, "
            "correlation_id, tenant_id, plan_id, actor, payload_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (new_id("evt"), change["change_id"] if change else None, event_type, utc(now),
             change["request_id"] if change else request_id,
             change["correlation_id"] if change else correlation_id,
             change["tenant_id"] if change else tenant_id,
             change["plan_id"] if change else None, actor, canonical_json(payload)),
        )

    def _outbox(self, change: dict[str, Any], topic: str, now: dt.datetime) -> None:
        payload = {
            "change_id": change["change_id"], "tenant_id": change["tenant_id"],
            "environment": change["environment"], "plan_id": change["plan_id"],
            "plan_digest": change["plan_digest"], "status": change["status"],
            "request_id": change["request_id"], "correlation_id": change["correlation_id"],
        }
        self.store.execute(
            "INSERT INTO outbox (message_id, change_id, topic, payload_json, status, created_at) "
            "VALUES (?,?,?,?, 'PENDING', ?)",
            (new_id("msg"), change["change_id"], topic, canonical_json(payload), utc(now)),
        )

    def _change(self, change_id: str, lock: bool = False) -> dict[str, Any]:
        row = self.store.one(f"SELECT * FROM change_requests WHERE change_id = ?{self.store.for_update if lock else ''}",
                             (change_id,))
        if row is None:
            raise KernelError("CHANGE_NOT_FOUND", 404)
        return row

    def _set_status(self, change: dict[str, Any], status: str, reason: str, now: dt.datetime) -> None:
        self.store.execute(
            "UPDATE change_requests SET status = ?, status_reason = ?, updated_at = ? WHERE change_id = ?",
            (status, reason, utc(now), change["change_id"]),
        )
        change["status"] = status
        self._outbox(change, f"openbao.change.{status.lower()}", now)

    def _authorize(self, principal: Principal, tenant_id: str, environment: str, role: str) -> None:
        if tenant_id not in principal.tenants or environment not in principal.environments:
            raise KernelError("TENANT_OR_ENVIRONMENT_NOT_AUTHORIZED", 403)
        if role not in principal.roles:
            raise KernelError("ROLE_NOT_AUTHORIZED", 403, role)

    def record_denial(self, error: KernelError, actor: str, environment: str) -> None:
        """Audit a refusal in its own transaction. Lock contention is already recorded."""
        if error.code == "ENVIRONMENT_LOCK_HELD":
            return
        kind = "POLICY_DENIED" if error.status == 403 else "SAFETY_DENIED"
        with self.store.transaction():
            self._event(kind, None, actor or "unknown",
                        {"code": error.code, "environment": environment}, self._now())

    # --- submission ------------------------------------------------------------------

    def validate_plan(self, plan: dict[str, Any], environment: str) -> tuple[list[dict[str, Any]], str]:
        if plan.get("planOnly") is not True:
            raise KernelError("PLAN_NOT_PLAN_ONLY")
        if plan.get("environment") != environment:
            raise KernelError("PLAN_ENVIRONMENT_MISMATCH", 409)
        source_sha = str(plan.get("planSourceSha", ""))
        if len(source_sha) != 40 or any(c not in "0123456789abcdef" for c in source_sha):
            raise KernelError("PLAN_SOURCE_SHA_INVALID")
        counts = plan.get("counts") or {}
        if counts.get("destroy") != 0:
            raise KernelError("PLAN_CONTAINS_DESTROY")
        if plan.get("warnings"):
            raise KernelError("PLAN_HAS_WARNINGS")
        operations = plan.get("operations")
        if not isinstance(operations, list) or not operations:
            raise KernelError("PLAN_HAS_NO_OPERATIONS")
        assert_secret_free(operations, "$.operations")
        classified, classes = [], []
        for sequence, operation in enumerate(operations):
            try:
                resource_kind, risk_class = self.authority.plan_operation(
                    str(operation.get("kind")), str(operation.get("action")))
            except AuthorityError as exc:
                raise KernelError("PLAN_OPERATION_REFUSED", 422, str(exc)) from exc
            classes.append(risk_class)
            classified.append({**operation, "sequence": sequence,
                               "resource_kind": resource_kind, "risk_class": risk_class})
        created = sum(1 for item in operations if item["action"] == "create")
        changed = sum(1 for item in operations if item["action"] == "update")
        if counts.get("create") != created or counts.get("change") != changed:
            raise KernelError("PLAN_COUNTS_INCONSISTENT")
        return classified, self.authority.effective_class(classes, environment)

    def submit(self, principal: Principal, *, tenant_id: str, environment: str,
               idempotency_key: str, request_id: str, correlation_id: str,
               plan: dict[str, Any], resource_fingerprint: str,
               max_attempts: int = DEFAULT_MAX_ATTEMPTS) -> dict[str, Any]:
        if not idempotency_key or len(idempotency_key) > 200:
            raise KernelError("IDEMPOTENCY_KEY_REQUIRED", 400)
        if not request_id or not correlation_id:
            raise KernelError("REQUEST_CONTEXT_REQUIRED", 400)
        self._authorize(principal, tenant_id, environment, "change.submit")
        exclusion_key = self.authority.exclusion_key(environment)
        operations, risk_class = self.validate_plan(plan, environment)
        plan_digest = digest(plan)
        authority_digest = digest(plan.get("authorityChecksums") or {})
        fingerprint = digest({"tenant": tenant_id, "environment": environment,
                              "plan_digest": plan_digest, "resource_fingerprint": resource_fingerprint})
        now = self._now()
        with self.store.transaction():
            existing = self.store.one(
                f"SELECT * FROM idempotency_keys WHERE tenant_id = ? AND idempotency_key = ?{self.store.for_update}",
                (tenant_id, idempotency_key))
            if existing:
                if existing["request_fingerprint"] != fingerprint:
                    raise KernelError("IDEMPOTENCY_CONFLICT", 409)
                change = self._change(existing["change_id"])
                self._event("IDEMPOTENT_REPLAY", change, principal.subject, {}, now)
                return change
            change_id, plan_id = new_id("chg"), new_id("plan")
            needs_approval = self.authority.classes[risk_class]["approvalRequired"]
            status = "AWAITING_APPROVAL" if needs_approval else "COMMITTED"
            change = {
                "change_id": change_id, "tenant_id": tenant_id, "environment": environment,
                "exclusion_key": exclusion_key, "request_id": request_id,
                "correlation_id": correlation_id, "submitted_by": principal.subject,
                "authorization_digest": principal.authorization_digest(tenant_id, environment),
                "production_gate_digest": self.authority.production_gate_digest(environment),
                "risk_class": risk_class, "idempotency_key": idempotency_key,
                "request_fingerprint": fingerprint, "plan_id": plan_id, "plan_digest": plan_digest,
                "source_sha": plan["planSourceSha"], "status": status, "status_reason": "",
                "attempt_count": 0, "max_attempts": max_attempts,
                "created_at": utc(now), "updated_at": utc(now),
            }
            columns = ", ".join(change)
            self.store.execute(
                f"INSERT INTO change_requests ({columns}) VALUES ({', '.join('?' * len(change))})",
                tuple(change.values()))
            self.store.execute(
                "INSERT INTO plans (plan_id, change_id, plan_digest, environment, source_sha, "
                "authority_digest, resource_fingerprint, create_count, change_count, destroy_count, "
                "plan_json, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (plan_id, change_id, plan_digest, environment, plan["planSourceSha"], authority_digest,
                 resource_fingerprint, plan["counts"]["create"], plan["counts"]["change"], 0,
                 canonical_json(plan), utc(now)))
            for operation in operations:
                self.store.execute(
                    "INSERT INTO operations (operation_id, plan_id, sequence, kind, action, name, "
                    "resource_kind, risk_class, payload_digest, status, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?, 'PLANNED', ?)",
                    (new_id("op"), plan_id, operation["sequence"], operation["kind"], operation["action"],
                     operation["name"], operation["resource_kind"], operation["risk_class"],
                     digest(operation.get("payload")), utc(now)))
            self.store.execute(
                "INSERT INTO idempotency_keys (tenant_id, idempotency_key, request_fingerprint, change_id, "
                "created_at, expires_at) VALUES (?,?,?,?,?,?)",
                (tenant_id, idempotency_key, fingerprint, change_id, utc(now),
                 utc(now + dt.timedelta(hours=int(self.authority.contract["idempotency"]["retentionHours"])))))
            self._event("CHANGE_SUBMITTED", change, principal.subject,
                        {"risk_class": risk_class, "plan_digest": plan_digest,
                         "operations": len(operations), "exclusion_key": exclusion_key}, now)
            self._outbox(change, f"openbao.change.{status.lower()}", now)
        return change

    # --- approval --------------------------------------------------------------------

    def approve(self, change_id: str, *, approver: str, plan_digest: str, environment: str,
                evidence_ref: str, valid_seconds: int) -> dict[str, Any]:
        now = self._now()
        if valid_seconds <= 0 or valid_seconds > self.authority.approval_max_seconds:
            raise KernelError("APPROVAL_VALIDITY_OUT_OF_RANGE")
        if not evidence_ref:
            raise KernelError("APPROVAL_EVIDENCE_REQUIRED")
        with self.store.transaction():
            change = self._change(change_id, lock=True)
            if change["status"] != "AWAITING_APPROVAL":
                raise KernelError("CHANGE_NOT_AWAITING_APPROVAL", 409, change["status"])
            if approver != self.authority.required_approver:
                raise KernelError("APPROVER_NOT_AUTHORIZED", 403)
            if approver == change["submitted_by"]:
                raise KernelError("APPROVER_NOT_INDEPENDENT", 403)
            if plan_digest != change["plan_digest"]:
                raise KernelError("APPROVAL_PLAN_DIGEST_MISMATCH", 409)
            if environment != change["environment"]:
                raise KernelError("APPROVAL_ENVIRONMENT_MISMATCH", 409)
            self.store.execute(
                "INSERT INTO approvals (approval_id, change_id, approver, plan_digest, environment, "
                "exclusion_key, evidence_ref, approved_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (new_id("apr"), change_id, approver, plan_digest, environment, change["exclusion_key"],
                 evidence_ref, utc(now), utc(now + dt.timedelta(seconds=valid_seconds))))
            self._set_status(change, "COMMITTED", "approved", now)
            self._event("CHANGE_APPROVED", change, approver, {"evidence_ref": evidence_ref}, now)
        return change

    # --- environment lock and fence ----------------------------------------------------

    def acquire_lock(self, environment: str, *, holder: str, purpose: str, run_ref: str,
                     ttl_seconds: int | None = None, change_id: str | None = None) -> Lease:
        default, maximum = self.authority.lease_bounds
        ttl = default if ttl_seconds is None else ttl_seconds
        if ttl <= 0 or ttl > maximum:
            raise KernelError("LEASE_TTL_OUT_OF_RANGE")
        if not holder or not purpose or not run_ref:
            raise KernelError("LEASE_IDENTITY_REQUIRED", 400)
        key = self.authority.exclusion_key(environment)
        now = self._now()
        with self.store.transaction():
            self.store.execute(
                "INSERT INTO fence_counters (exclusion_key, last_token) VALUES (?, 0) "
                "ON CONFLICT (exclusion_key) DO NOTHING", (key,))
            self.store.one(f"SELECT last_token FROM fence_counters WHERE exclusion_key = ?{self.store.for_update}",
                           (key,))
            current = self.store.one("SELECT * FROM environment_locks WHERE exclusion_key = ?", (key,))
            if current and parse_utc(current["expires_at"]) > now and current["holder"] != holder:
                self._event("LOCK_DENIED", None, holder,
                            {"exclusion_key": key, "held_by": current["holder"],
                             "held_for": current["purpose"], "expires_at": current["expires_at"]}, now)
                raise KernelError("ENVIRONMENT_LOCK_HELD", 423,
                                  f"{current['holder']} ({current['purpose']}) until {current['expires_at']}")
            self.store.execute("UPDATE fence_counters SET last_token = last_token + 1 WHERE exclusion_key = ?",
                               (key,))
            token = int(self.store.one("SELECT last_token FROM fence_counters WHERE exclusion_key = ?",
                                       (key,))["last_token"])
            expires = utc(now + dt.timedelta(seconds=ttl))
            self.store.execute("DELETE FROM environment_locks WHERE exclusion_key = ?", (key,))
            self.store.execute(
                "INSERT INTO environment_locks (exclusion_key, holder, fence_token, purpose, change_id, "
                "run_ref, acquired_at, heartbeat_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (key, holder, token, purpose, change_id, run_ref, utc(now), utc(now), expires))
            self._event("LOCK_ACQUIRED", None, holder,
                        {"exclusion_key": key, "fence_token": token, "purpose": purpose,
                         "run_ref": run_ref, "expires_at": expires,
                         "took_over_expired_from": current["holder"] if current else ""}, now)
        return Lease(key, holder, token, expires)

    def _check_fence(self, lease: Lease, now: dt.datetime) -> None:
        counter = self.store.one(
            f"SELECT last_token FROM fence_counters WHERE exclusion_key = ?{self.store.for_update}",
            (lease.exclusion_key,))
        current = self.store.one("SELECT * FROM environment_locks WHERE exclusion_key = ?",
                                 (lease.exclusion_key,))
        reason = ""
        if current is None or counter is None:
            reason = "lock_absent"
        elif current["holder"] != lease.holder:
            reason = "lease_holder_changed"
        elif int(current["fence_token"]) != lease.fence_token or int(counter["last_token"]) != lease.fence_token:
            reason = "fence_token_superseded"
        elif parse_utc(current["expires_at"]) <= now:
            reason = "lease_expired"
        if reason:
            raise KernelError("LEASE_FENCE_DENIED", 409, reason)

    def check_fence(self, lease: Lease) -> None:
        with self.store.transaction():
            self._check_fence(lease, self._now())

    def heartbeat(self, lease: Lease, ttl_seconds: int | None = None) -> Lease:
        default, maximum = self.authority.lease_bounds
        ttl = default if ttl_seconds is None else ttl_seconds
        if ttl <= 0 or ttl > maximum:
            raise KernelError("LEASE_TTL_OUT_OF_RANGE")
        now = self._now()
        with self.store.transaction():
            self._check_fence(lease, now)
            expires = utc(now + dt.timedelta(seconds=ttl))
            self.store.execute(
                "UPDATE environment_locks SET heartbeat_at = ?, expires_at = ? WHERE exclusion_key = ?",
                (utc(now), expires, lease.exclusion_key))
        return Lease(lease.exclusion_key, lease.holder, lease.fence_token, expires)

    def release_lock(self, lease: Lease) -> None:
        now = self._now()
        with self.store.transaction():
            current = self.store.one(
                f"SELECT * FROM environment_locks WHERE exclusion_key = ?{self.store.for_update}",
                (lease.exclusion_key,))
            if (current is None or current["holder"] != lease.holder
                    or int(current["fence_token"]) != lease.fence_token):
                raise KernelError("NOT_LOCK_HOLDER", 409)
            self.store.execute("DELETE FROM environment_locks WHERE exclusion_key = ?", (lease.exclusion_key,))
            self._event("LOCK_RELEASED", None, lease.holder,
                        {"exclusion_key": lease.exclusion_key, "fence_token": lease.fence_token}, now)

    def lock_status(self, environment: str) -> dict[str, Any] | None:
        key = self.authority.exclusion_key(environment)
        row = self.store.one("SELECT exclusion_key, holder, fence_token, purpose, change_id, run_ref, "
                             "acquired_at, heartbeat_at, expires_at FROM environment_locks "
                             "WHERE exclusion_key = ?", (key,))
        if row:
            row["expired"] = parse_utc(row["expires_at"]) <= self._now()
        return row

    # --- execution ---------------------------------------------------------------------

    def _plan(self, change: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        plan_row = self.store.one("SELECT * FROM plans WHERE plan_id = ?", (change["plan_id"],))
        if plan_row is None:
            raise KernelError("PLAN_NOT_FOUND", 404)
        return plan_row, json.loads(plan_row["plan_json"])

    def begin_attempt(self, change_id: str, lease: Lease, principal: Principal,
                      resource_fingerprint: str) -> Attempt:
        now = self._now()
        with self.store.transaction():
            change = self._change(change_id, lock=True)
            if lease.exclusion_key != change["exclusion_key"]:
                raise KernelError("LEASE_WRONG_TARGET", 409)
            self._check_fence(lease, now)
            if change["status"] not in EXECUTABLE_STATUSES:
                raise KernelError("CHANGE_NOT_EXECUTABLE", 409, change["status"])
            self._authorize(principal, change["tenant_id"], change["environment"], "change.execute")
            unresolved = self.store.one(
                "SELECT COUNT(*) AS n FROM dispatch_intents WHERE change_id = ? AND status IN (?, ?)",
                (change_id, *UNRESOLVED_INTENTS))
            if unresolved and int(unresolved["n"]):
                raise KernelError("UNRESOLVED_DISPATCH", 409, "reconcile unknown outcomes first")
            if self.authority.classes[change["risk_class"]]["approvalRequired"]:
                approval = self.store.one(
                    "SELECT * FROM approvals WHERE change_id = ? ORDER BY approved_at DESC", (change_id,))
                if (approval is None or approval["plan_digest"] != change["plan_digest"]
                        or approval["exclusion_key"] != change["exclusion_key"]):
                    raise KernelError("APPROVAL_MISSING_OR_UNBOUND", 403)
                if parse_utc(approval["expires_at"]) <= now:
                    raise KernelError("APPROVAL_EXPIRED", 403)
            plan_row, plan = self._plan(change)
            if digest(plan) != change["plan_digest"] or plan_row["plan_digest"] != change["plan_digest"]:
                raise KernelError("PLAN_DIGEST_CHANGED", 409)
            recorded = plan.get("authorityChecksums") or {}
            try:
                current = self.authority.current_authority_checksums(recorded)
            except AuthorityError as exc:
                raise KernelError("AUTHORITY_UNREADABLE", 409, str(exc)) from exc
            if current != recorded:
                raise KernelError("PLAN_STALE_AUTHORITY_CHANGED", 409)
            if resource_fingerprint != plan_row["resource_fingerprint"]:
                raise KernelError("RESOURCE_FINGERPRINT_CHANGED", 409)
            if self.authority.production_gate_digest(change["environment"]) != change["production_gate_digest"]:
                raise KernelError("PRODUCTION_GATE_CHANGED", 409)
            if not self.authority.production_gate(change["environment"])["runtimeApplyAuthorized"]:
                raise KernelError("RUNTIME_APPLY_NOT_AUTHORIZED", 403)
            if int(change["attempt_count"]) >= int(change["max_attempts"]):
                raise KernelError("ATTEMPTS_EXHAUSTED", 409)
            number = int(change["attempt_count"]) + 1
            attempt_id = new_id("att")
            self.store.execute(
                "INSERT INTO attempts (attempt_id, change_id, attempt_number, holder, fence_token, "
                "started_at, outcome) VALUES (?,?,?,?,?,?, 'STARTED')",
                (attempt_id, change_id, number, lease.holder, lease.fence_token, utc(now)))
            self.store.execute("UPDATE change_requests SET attempt_count = ? WHERE change_id = ?",
                               (number, change_id))
            self._set_status(change, "EXECUTING", f"attempt {number}", now)
            self._event("ATTEMPT_STARTED", change, principal.subject,
                        {"attempt": number, "fence_token": lease.fence_token}, now)
            rows = self.store.all("SELECT * FROM operations WHERE plan_id = ? ORDER BY sequence",
                                  (change["plan_id"],))
        planned = plan["operations"]
        operations = tuple(
            {**planned[int(row["sequence"])], "operation_id": row["operation_id"],
             "status": row["status"], "sequence": int(row["sequence"])}
            for row in rows)
        for item in operations:
            if digest(item.get("payload")) != next(r["payload_digest"] for r in rows
                                                   if r["operation_id"] == item["operation_id"]):
                raise KernelError("OPERATION_PAYLOAD_CHANGED", 409)
        return Attempt(attempt_id, change_id, number, lease.fence_token, operations)

    def intend(self, attempt: Attempt, operation_id: str, lease: Lease) -> str:
        """Persist dispatch intent after a fresh fence check. No intent, no OpenBao call."""
        now = self._now()
        with self.store.transaction():
            change = self._change(attempt.change_id, lock=True)
            self._check_fence(lease, now)
            if lease.fence_token != attempt.fence_token:
                raise KernelError("LEASE_FENCE_DENIED", 409, "attempt_fence_mismatch")
            if change["status"] != "EXECUTING":
                raise KernelError("CHANGE_NOT_EXECUTING", 409, change["status"])
            operation = self.store.one("SELECT * FROM operations WHERE operation_id = ? AND plan_id = ?",
                                       (operation_id, change["plan_id"]))
            if operation is None:
                raise KernelError("OPERATION_NOT_IN_PLAN", 409)
            if operation["status"] in ("CONFIRMED", "UNKNOWN"):
                raise KernelError("OPERATION_NOT_DISPATCHABLE", 409, operation["status"])
            intent_id = new_id("int")
            self.store.execute(
                "INSERT INTO dispatch_intents (intent_id, change_id, attempt_id, operation_id, exclusion_key, "
                "fence_token, status, created_at) VALUES (?,?,?,?,?,?, 'INTENDED', ?)",
                (intent_id, attempt.change_id, attempt.attempt_id, operation_id, lease.exclusion_key,
                 lease.fence_token, utc(now)))
            self._event("DISPATCH_INTENDED", change, lease.holder,
                        {"operation_id": operation_id, "fence_token": lease.fence_token}, now)
        return intent_id

    def resolve_intent(self, intent_id: str, outcome: str, resolution: str) -> None:
        """Record what readback proved. Recording truth never needs the lease."""
        if outcome not in ("CONFIRMED", "FAILED", "UNKNOWN"):
            raise KernelError("INVALID_OUTCOME", 400)
        now = self._now()
        with self.store.transaction():
            intent = self.store.one(f"SELECT * FROM dispatch_intents WHERE intent_id = ?{self.store.for_update}",
                                    (intent_id,))
            if intent is None:
                raise KernelError("INTENT_NOT_FOUND", 404)
            if intent["status"] not in UNRESOLVED_INTENTS:
                raise KernelError("INTENT_ALREADY_RESOLVED", 409, intent["status"])
            if intent["status"] == "UNKNOWN" and outcome == "UNKNOWN":
                return
            self.store.execute(
                "UPDATE dispatch_intents SET status = ?, resolved_at = ?, resolution = ? WHERE intent_id = ?",
                (outcome, utc(now) if outcome != "UNKNOWN" else None, resolution, intent_id))
            self.store.execute("UPDATE operations SET status = ?, updated_at = ? WHERE operation_id = ?",
                               (outcome, utc(now), intent["operation_id"]))
            change = self._change(intent["change_id"])
            self._event(f"DISPATCH_{outcome}", change, "actuator",
                        {"operation_id": intent["operation_id"], "resolution": resolution}, now)

    def confirm_without_dispatch(self, attempt: Attempt, operation_id: str, lease: Lease, reason: str) -> None:
        """Readback already shows the planned state; record it without calling OpenBao."""
        intent_id = self.intend(attempt, operation_id, lease)
        self.resolve_intent(intent_id, "CONFIRMED", reason)

    def finish_attempt(self, attempt: Attempt) -> str:
        now = self._now()
        with self.store.transaction():
            change = self._change(attempt.change_id, lock=True)
            statuses = [row["status"] for row in self.store.all(
                "SELECT status FROM operations WHERE plan_id = ?", (change["plan_id"],))]
            unresolved = self.store.one(
                "SELECT COUNT(*) AS n FROM dispatch_intents WHERE attempt_id = ? AND status = 'INTENDED'",
                (attempt.attempt_id,))
            if unresolved and int(unresolved["n"]):
                self.store.execute(
                    "UPDATE dispatch_intents SET status = 'UNKNOWN', resolution = 'unresolved_at_finish' "
                    "WHERE attempt_id = ? AND status = 'INTENDED'", (attempt.attempt_id,))
                statuses.append("UNKNOWN")
            if all(status == "CONFIRMED" for status in statuses):
                outcome, status = "SUCCEEDED", "SUCCEEDED"
            elif "UNKNOWN" in statuses:
                outcome, status = "RECONCILIATION_REQUIRED", "RECONCILIATION_REQUIRED"
            elif int(change["attempt_count"]) < int(change["max_attempts"]):
                outcome, status = "RETRY", "RETRY"
            else:
                outcome, status = "DEAD_LETTER", "DEAD_LETTER"
            self.store.execute("UPDATE attempts SET outcome = ?, finished_at = ? WHERE attempt_id = ?",
                               (outcome, utc(now), attempt.attempt_id))
            self._set_status(change, status, f"attempt {attempt.number} {outcome.lower()}", now)
            self._event(f"CHANGE_{status}", change, "actuator", {"attempt": attempt.number}, now)
        return status

    # --- recovery ----------------------------------------------------------------------

    def recover_interrupted(self, change_id: str, lease: Lease) -> str:
        """A newer lease holder converts an abandoned EXECUTING attempt into UNKNOWN outcomes."""
        now = self._now()
        with self.store.transaction():
            change = self._change(change_id, lock=True)
            self._check_fence(lease, now)
            if change["status"] != "EXECUTING":
                raise KernelError("CHANGE_NOT_EXECUTING", 409, change["status"])
            attempt = self.store.one(
                "SELECT * FROM attempts WHERE change_id = ? AND outcome = 'STARTED' "
                "ORDER BY attempt_number DESC", (change_id,))
            if attempt is None or int(attempt["fence_token"]) >= lease.fence_token:
                raise KernelError("ATTEMPT_NOT_ABANDONED", 409)
            self.store.execute(
                "UPDATE dispatch_intents SET status = 'UNKNOWN', resolution = 'holder_lost_lease' "
                "WHERE attempt_id = ? AND status = 'INTENDED'", (attempt["attempt_id"],))
            self.store.execute(
                "UPDATE operations SET status = 'UNKNOWN', updated_at = ? WHERE operation_id IN "
                "(SELECT operation_id FROM dispatch_intents WHERE attempt_id = ? AND status = 'UNKNOWN')",
                (utc(now), attempt["attempt_id"]))
            self.store.execute(
                "UPDATE attempts SET outcome = 'RECONCILIATION_REQUIRED', finished_at = ?, detail = ? "
                "WHERE attempt_id = ?", (utc(now), "holder_lost_lease", attempt["attempt_id"]))
            self._set_status(change, "RECONCILIATION_REQUIRED", "interrupted attempt", now)
            self._event("ATTEMPT_ABANDONED", change, lease.holder,
                        {"attempt": attempt["attempt_number"], "stale_fence_token": attempt["fence_token"]}, now)
        return "RECONCILIATION_REQUIRED"

    def unknown_operations(self, change_id: str) -> list[dict[str, Any]]:
        change = self._change(change_id)
        _, plan = self._plan(change)
        rows = self.store.all(
            "SELECT o.operation_id, o.sequence, i.intent_id FROM dispatch_intents i "
            "JOIN operations o ON o.operation_id = i.operation_id "
            "WHERE i.change_id = ? AND i.status = 'UNKNOWN' ORDER BY o.sequence", (change_id,))
        return [{**plan["operations"][int(row["sequence"])], "operation_id": row["operation_id"],
                 "intent_id": row["intent_id"]} for row in rows]

    def reconcile_unknown(self, change_id: str, lease: Lease, readback: dict[str, bool],
                          evidence_ref: str) -> str:
        """Resolve UNKNOWN outcomes from readback only. Never resubmits anything."""
        if not evidence_ref:
            raise KernelError("RECONCILIATION_EVIDENCE_REQUIRED")
        pending = self.unknown_operations(change_id)
        if not pending:
            raise KernelError("NOTHING_TO_RECONCILE", 409)
        now = self._now()
        with self.store.transaction():
            change = self._change(change_id, lock=True)
            self._check_fence(lease, now)
            if change["status"] != "RECONCILIATION_REQUIRED":
                raise KernelError("CHANGE_NOT_IN_RECONCILIATION", 409, change["status"])
            for item in pending:
                if item["operation_id"] not in readback:
                    raise KernelError("READBACK_INCOMPLETE", 409, item["operation_id"])
                outcome = "CONFIRMED" if readback[item["operation_id"]] else "FAILED"
                self.store.execute(
                    "UPDATE dispatch_intents SET status = ?, resolved_at = ?, resolution = ? WHERE intent_id = ?",
                    (outcome, utc(now), f"readback:{evidence_ref}", item["intent_id"]))
                self.store.execute("UPDATE operations SET status = ?, updated_at = ? WHERE operation_id = ?",
                                   (outcome, utc(now), item["operation_id"]))
            statuses = [row["status"] for row in self.store.all(
                "SELECT status FROM operations WHERE plan_id = ?", (change["plan_id"],))]
            if all(status == "CONFIRMED" for status in statuses):
                status = "SUCCEEDED"
            elif int(change["attempt_count"]) < int(change["max_attempts"]):
                status = "RETRY"
            else:
                status = "DEAD_LETTER"
            self._set_status(change, status, "reconciled from readback", now)
            self._event("CHANGE_RECONCILED", change, lease.holder,
                        {"evidence_ref": evidence_ref, "result": status}, now)
        return status

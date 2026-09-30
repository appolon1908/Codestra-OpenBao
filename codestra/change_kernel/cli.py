"""Command-line entry point used by protected workflows and operators.

Output is one JSON object on stdout. Refusals exit non-zero with the stable
error code on stderr. No command prints tokens or secret payloads.

Exit codes: 0 success, 2 refused, 3 environment lock held, 4 fence denied,
5 store or authority unavailable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import actuator
from .authority import Authority, AuthorityError
from .canonical import SecretMaterialError, digest
from .kernel import ChangeKernel, KernelError, Lease, Principal
from .store import Store, StoreError

DATABASE_ENV = "OPENBAO_CHANGE_KERNEL_DATABASE_URL"
LEASE_FILE_ENV = "OPENBAO_CHANGE_KERNEL_LEASE_FILE"


def _kernel(args: argparse.Namespace) -> ChangeKernel:
    url = args.database or os.environ.get(DATABASE_ENV, "")
    if not url:
        raise StoreError(f"{DATABASE_ENV} or --database is required")
    store = Store(url)
    store.migrate()
    return ChangeKernel(store, Authority())


def _emit(value: Any) -> None:
    print(json.dumps(value, sort_keys=True))


def _lease_path(args: argparse.Namespace) -> Path:
    path = args.lease_file or os.environ.get(LEASE_FILE_ENV, "")
    if not path:
        raise KernelError("LEASE_FILE_REQUIRED", 400)
    return Path(path)


def _read_lease(args: argparse.Namespace) -> Lease:
    try:
        data = json.loads(_lease_path(args).read_text(encoding="utf-8"))
        return Lease(data["exclusionKey"], data["holder"], int(data["fenceToken"]), data["expiresAt"])
    except (OSError, ValueError, KeyError) as exc:
        raise KernelError("LEASE_FILE_UNREADABLE", 400) from exc


def _write_lease(args: argparse.Namespace, lease: Lease) -> dict[str, Any]:
    value = {"exclusionKey": lease.exclusion_key, "holder": lease.holder,
             "fenceToken": lease.fence_token, "expiresAt": lease.expires_at}
    path = _lease_path(args)
    old = os.umask(0o077)
    try:
        partial = path.with_name(path.name + ".partial")
        partial.write_text(json.dumps(value), encoding="utf-8")
        partial.replace(path)
    finally:
        os.umask(old)
    return value


def _principal(args: argparse.Namespace, roles: set[str]) -> Principal:
    subject = args.subject or os.environ.get("GITHUB_ACTOR", "")
    if not subject:
        raise KernelError("PRINCIPAL_SUBJECT_REQUIRED", 400)
    return Principal(subject, frozenset({args.tenant}), frozenset({args.environment}), frozenset(roles))


def live_fingerprint(live_dir: Path) -> str:
    """Digest of the sanitized live-state files that `scripts/plan.sh` collects."""
    entries = {}
    for path in sorted(item for item in live_dir.rglob("*") if item.is_file()):
        entries[path.relative_to(live_dir).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not entries:
        raise KernelError("LIVE_STATE_EMPTY", 400)
    return digest(entries)


def _verified_plan(args: argparse.Namespace) -> dict[str, Any]:
    plan_path, checksum_path = Path(args.plan), Path(args.checksum)
    lines = checksum_path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1:
        raise KernelError("PLAN_CHECKSUM_LINE_COUNT", 422)
    recorded, _, name = lines[0].partition("  ")
    if name.lstrip("*") != plan_path.name:
        raise KernelError("PLAN_CHECKSUM_NAMES_OTHER_FILE", 422)
    if hashlib.sha256(plan_path.read_bytes()).hexdigest() != recorded:
        raise KernelError("PLAN_CHECKSUM_MISMATCH", 422)
    if args.expected_plan_sha256 and args.expected_plan_sha256 != recorded:
        raise KernelError("PLAN_REVIEWED_DIGEST_MISMATCH", 422)
    return json.loads(plan_path.read_text(encoding="utf-8"))


def cmd_migrate(args: argparse.Namespace) -> None:
    kernel = _kernel(args)
    _emit({"migrated": True, "dialect": kernel.store.dialect})


def cmd_lock_acquire(args: argparse.Namespace) -> None:
    kernel = _kernel(args)
    lease = kernel.acquire_lock(args.environment, holder=args.holder, purpose=args.purpose,
                                run_ref=args.run_ref, ttl_seconds=args.ttl, change_id=args.change_id)
    _emit(_write_lease(args, lease))


def cmd_lock_heartbeat(args: argparse.Namespace) -> None:
    kernel = _kernel(args)
    _emit(_write_lease(args, kernel.heartbeat(_read_lease(args), args.ttl)))


def cmd_lock_check(args: argparse.Namespace) -> None:
    kernel = _kernel(args)
    lease = _read_lease(args)
    if args.environment and lease.exclusion_key != kernel.authority.exclusion_key(args.environment):
        raise KernelError("LEASE_WRONG_TARGET", 409)
    kernel.check_fence(lease)
    _emit({"fence": "VALID", "exclusionKey": lease.exclusion_key})


def cmd_live_fingerprint(args: argparse.Namespace) -> None:
    _emit({"liveStateSha256": live_fingerprint(Path(args.live_dir))})


def cmd_lock_release(args: argparse.Namespace) -> None:
    kernel = _kernel(args)
    kernel.release_lock(_read_lease(args))
    _lease_path(args).unlink(missing_ok=True)
    _emit({"released": True})


def cmd_lock_status(args: argparse.Namespace) -> None:
    _emit({"lock": _kernel(args).lock_status(args.environment)})


def cmd_submit(args: argparse.Namespace) -> None:
    kernel = _kernel(args)
    plan = _verified_plan(args)
    recorded = plan.get("liveStateSha256")
    if not isinstance(recorded, str) or len(recorded) != 64:
        raise KernelError("PLAN_LIVE_STATE_UNBOUND", 422)
    change = kernel.submit(_principal(args, {"change.submit"}), tenant_id=args.tenant,
                           environment=args.environment, idempotency_key=args.idempotency_key,
                           request_id=args.request_id, correlation_id=args.correlation_id,
                           plan=plan, resource_fingerprint=recorded)
    _emit({key: change[key] for key in ("change_id", "status", "plan_digest", "risk_class", "exclusion_key")})


def cmd_approve(args: argparse.Namespace) -> None:
    kernel = _kernel(args)
    change = kernel.approve(args.change_id, approver=args.approver, plan_digest=args.plan_digest,
                            environment=args.environment, evidence_ref=args.evidence_ref,
                            valid_seconds=args.valid_seconds)
    _emit({"change_id": change["change_id"], "status": change["status"]})


def cmd_apply(args: argparse.Namespace) -> None:
    kernel = _kernel(args)
    status = actuator.execute(kernel, args.change_id, _read_lease(args), _principal(args, {"change.execute"}),
                              live_fingerprint(Path(args.live_dir)))
    _emit({"change_id": args.change_id, "status": status})
    if status != "SUCCEEDED":
        raise KernelError(f"CHANGE_{status}", 2)


def cmd_reconcile(args: argparse.Namespace) -> None:
    kernel = _kernel(args)
    status = actuator.reconcile(kernel, args.change_id, _read_lease(args), args.evidence_ref)
    _emit({"change_id": args.change_id, "status": status})


def cmd_recover(args: argparse.Namespace) -> None:
    kernel = _kernel(args)
    _emit({"change_id": args.change_id, "status": kernel.recover_interrupted(args.change_id, _read_lease(args))})


def cmd_status(args: argparse.Namespace) -> None:
    kernel = _kernel(args)
    change = kernel.store.one(
        "SELECT change_id, tenant_id, environment, exclusion_key, risk_class, status, status_reason, "
        "plan_digest, source_sha, attempt_count, max_attempts, updated_at FROM change_requests "
        "WHERE change_id = ?", (args.change_id,))
    if change is None:
        raise KernelError("CHANGE_NOT_FOUND", 404)
    change["operations"] = kernel.store.all(
        "SELECT sequence, kind, action, name, status FROM operations WHERE plan_id = "
        "(SELECT plan_id FROM change_requests WHERE change_id = ?) ORDER BY sequence", (args.change_id,))
    _emit(change)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="python3 -m codestra.change_kernel.cli")
    root.add_argument("--database")
    commands = root.add_subparsers(dest="command", required=True)

    def add(name, handler, *arguments):
        sub = commands.add_parser(name)
        for argument in arguments:
            optional = argument.endswith("?")
            argument = argument.rstrip("?")
            sub.add_argument(f"--{argument}", required=not optional and argument not in {
                "ttl", "change-id", "subject", "lease-file", "expected-plan-sha256"})
        sub.set_defaults(handler=handler)
        return sub

    add("migrate", cmd_migrate)
    add("live-fingerprint", cmd_live_fingerprint, "live-dir")
    add("lock-check", cmd_lock_check, "lease-file", "environment?")
    for name, handler in (("lock-heartbeat", cmd_lock_heartbeat), ("lock-release", cmd_lock_release)):
        add(name, handler, "lease-file", "ttl")
    add("lock-acquire", cmd_lock_acquire, "environment", "holder", "purpose", "run-ref", "ttl",
        "change-id", "lease-file")
    add("lock-status", cmd_lock_status, "environment")
    add("submit", cmd_submit, "environment", "tenant", "idempotency-key", "request-id", "correlation-id",
        "plan", "checksum", "expected-plan-sha256", "subject")
    add("approve", cmd_approve, "change-id", "approver", "plan-digest", "environment", "evidence-ref",
        "valid-seconds")
    add("apply", cmd_apply, "change-id", "environment", "tenant", "live-dir", "subject", "lease-file")
    add("reconcile", cmd_reconcile, "change-id", "evidence-ref", "lease-file")
    add("recover", cmd_recover, "change-id", "lease-file")
    add("status", cmd_status, "change-id")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    for name in ("ttl", "valid_seconds"):
        if getattr(args, name, None) is not None:
            setattr(args, name, int(getattr(args, name)))
    try:
        args.handler(args)
    except KernelError as exc:
        print(f"OPENBAO_CHANGE_KERNEL=REFUSED CODE={exc.code}", file=sys.stderr)
        if exc.code == "ENVIRONMENT_LOCK_HELD":
            print(f"HELD_BY={exc.detail}", file=sys.stderr)
            return 3
        return 4 if exc.code == "LEASE_FENCE_DENIED" else 2
    except SecretMaterialError as exc:
        print(f"OPENBAO_CHANGE_KERNEL=REFUSED CODE=SECRET_MATERIAL {exc}", file=sys.stderr)
        return 2
    except (StoreError, AuthorityError) as exc:
        print(f"OPENBAO_CHANGE_KERNEL=UNAVAILABLE ERROR={exc}", file=sys.stderr)
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

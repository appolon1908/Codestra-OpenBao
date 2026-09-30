"""The single privileged actuator: the only code that issues OpenBao mutations.

Order per operation: readback, fenced dispatch intent, one `bao` call, readback,
resolution. A call is never judged by its exit status alone; only readback can
confirm an operation. Command output is discarded so no response body reaches
logs or the control plane.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, Protocol

from .kernel import Attempt, ChangeKernel, KernelError, Lease, Principal

ROOT = Path(__file__).resolve().parents[2]
EXECUTION_ORDER = ("auth_plugin", "secret_engine", "secret_engine_config", "auth_method",
                   "policy", "auth_config", "jwt_role")
COMMAND_TIMEOUT_SECONDS = 120


class Runner(Protocol):
    def __call__(self, argv: list[str], timeout: int) -> int: ...


def bao_runner(argv: list[str], timeout: int) -> int:
    result = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=timeout, check=False)
    return result.returncode


def _load_readback() -> Callable[[dict[str, Any]], None]:
    spec = importlib.util.spec_from_file_location("verify_applied_plan", ROOT / "scripts/verify_applied_plan.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("readback_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verify


def default_readback(operation: dict[str, Any]) -> bool:
    try:
        _load_readback()(operation)
    except (ValueError, KeyError, json.JSONDecodeError):
        return False
    return True


def command(operation: dict[str, Any], payload_file: Path, work: Path) -> list[str]:
    kind, action, name, payload = operation["kind"], operation["action"], operation["name"], operation["payload"]
    key = f"{kind}:{action}"
    if key == "auth_plugin:create":
        return ["bao", "plugin", "register", f"-sha256={payload['sha256']}", f"-command={payload['command']}",
                f"-version={payload['version']}", "auth", payload["name"]]
    if key == "secret_engine:create":
        return ["bao", "secrets", "enable", f"-path={payload['path']}",
                f"-description={payload['description']}", "-version=2", "kv"]
    if key == "auth_method:create":
        return ["bao", "auth", "enable", f"-path={payload['path']}", f"-plugin-name={payload['plugin_name']}",
                f"-plugin-version={payload['plugin_version']}", "plugin"]
    if kind == "policy" and action in {"create", "update"}:
        policy_file = work / "policy.hcl"
        policy_file.write_text(payload["policy"], encoding="utf-8")
        return ["bao", "policy", "write", name, str(policy_file)]
    if kind in {"secret_engine_config", "auth_config", "jwt_role"} and action in {"create", "update"}:
        return ["bao", "write", name, f"@{payload_file}"]
    raise KernelError("UNSUPPORTED_OR_DESTRUCTIVE_OPERATION", 422, key)


def ordered(operations: tuple[dict[str, Any], ...]) -> list[dict[str, Any]]:
    rank = {kind: index for index, kind in enumerate(EXECUTION_ORDER)}
    return sorted(operations, key=lambda item: (rank.get(item["kind"], 99), item["sequence"]))


def execute(kernel: ChangeKernel, change_id: str, lease: Lease, principal: Principal,
            resource_fingerprint: str, *, runner: Runner = bao_runner,
            readback: Callable[[dict[str, Any]], bool] = default_readback) -> str:
    attempt: Attempt = kernel.begin_attempt(change_id, lease, principal, resource_fingerprint)
    old_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="openbao-change-") as directory:
            work = Path(directory)
            for operation in ordered(attempt.operations):
                if operation["status"] == "CONFIRMED":
                    continue
                if readback(operation):
                    kernel.confirm_without_dispatch(attempt, operation["operation_id"], lease,
                                                    "already_in_planned_state")
                    continue
                payload_file = work / "payload.json"
                payload_file.write_text(json.dumps(operation["payload"]), encoding="utf-8")
                argv = command(operation, payload_file, work)
                intent_id = kernel.intend(attempt, operation["operation_id"], lease)
                try:
                    exit_code = runner(argv, COMMAND_TIMEOUT_SECONDS)
                except (subprocess.TimeoutExpired, OSError):
                    kernel.resolve_intent(intent_id, "UNKNOWN", "call_interrupted")
                    break
                finally:
                    for leftover in work.iterdir():
                        leftover.unlink()
                if readback(operation):
                    kernel.resolve_intent(intent_id, "CONFIRMED", f"readback_match exit={exit_code}")
                elif exit_code != 0:
                    kernel.resolve_intent(intent_id, "FAILED", f"readback_absent exit={exit_code}")
                    break
                else:
                    kernel.resolve_intent(intent_id, "UNKNOWN", "accepted_but_readback_mismatch")
                    break
    finally:
        os.umask(old_umask)
    return kernel.finish_attempt(attempt)


def reconcile(kernel: ChangeKernel, change_id: str, lease: Lease, evidence_ref: str, *,
              readback: Callable[[dict[str, Any]], bool] = default_readback) -> str:
    results = {item["operation_id"]: readback(item) for item in kernel.unknown_operations(change_id)}
    return kernel.reconcile_unknown(change_id, lease, results, evidence_ref)

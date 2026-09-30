"""The reconciliation engine: classify desired-versus-live drift and record it.

Detection only. Drift never starts a mutation; a correction is a new saved
plan that goes through submit, review, approval and the actuator like any
other change.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import assert_secret_free, canonical_json, digest
from .kernel import ChangeKernel, new_id, utc

SECURITY_CRITICAL_KINDS = frozenset({"auth_plugin", "auth_method", "auth_config", "jwt_role"})
DISABLED_BY_DEFAULT_MOUNTS = ("database/", "pki-codestra/", "transit-codestra/")


def classify(plan: dict[str, Any], live_dir: Path, engines: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for operation in plan.get("operations", []):
        classification = "MISSING" if operation["action"] == "create" else "DRIFTED"
        severity = "critical" if operation["kind"] in SECURITY_CRITICAL_KINDS else "warning"
        findings.append({"resource_kind": operation["kind"], "resource_name": operation["name"],
                         "classification": classification, "severity": severity,
                         "detail": {"action": operation["action"], "payload_digest": digest(operation.get("payload"))}})
    for warning in plan.get("warnings", []):
        text = str(warning)
        if "file-audit" in text or "replay-protected plugin" in text or "plugin version identity" in text:
            classification, severity = "SECURITY_CRITICAL", "critical"
        elif text.startswith("unmanaged"):
            classification, severity = "UNMANAGED", "warning"
        elif "prohibited" in text:
            classification, severity = "CONFLICT", "critical"
        else:
            classification, severity = "CONFLICT", "warning"
        findings.append({"resource_kind": "plan_warning", "resource_name": text.split(" ")[0],
                         "classification": classification, "severity": severity, "detail": {"warning": text}})
    mounts_path = live_dir / "mounts.json"
    mounts = json.loads(mounts_path.read_text(encoding="utf-8")) if mounts_path.is_file() else {}
    mounts = mounts.get("data", mounts) if isinstance(mounts, dict) else {}
    disabled = {item["path"] for item in engines.get("engines", []) if item.get("enabledByDefault") is False}
    for path in DISABLED_BY_DEFAULT_MOUNTS:
        if path in disabled and path in mounts:
            findings.append({"resource_kind": "secret_engine", "resource_name": path,
                             "classification": "DISABLED", "severity": "critical",
                             "detail": {"reason": "mount enabled while authority keeps it disabled"}})
    for finding in findings:
        assert_secret_free(finding["detail"], "$.detail")
    return findings


def record_run(kernel: ChangeKernel, *, environment: str, plan: dict[str, Any], live_dir: Path,
               lease_state_before: str, lease_state_after: str) -> dict[str, Any]:
    engines = json.loads((kernel.authority.root / "config/secrets/engines.v1.json").read_text(encoding="utf-8"))
    kernel.authority.exclusion_key(environment)
    if plan.get("environment") != environment:
        raise ValueError("plan_environment_mismatch")
    consistent = lease_state_before == "FREE" and lease_state_after == "FREE"
    findings = classify(plan, live_dir, engines) if consistent else []
    if not consistent:
        status = "INCONSISTENT"
    elif findings:
        status = "DRIFT_DETECTED"
    else:
        status = "IN_SYNC"
    now = kernel.clock()
    run_id = new_id("rec")
    summary = {"findings": len(findings), "lease_before": lease_state_before, "lease_after": lease_state_after,
               "by_classification": {}}
    for finding in findings:
        key = finding["classification"]
        summary["by_classification"][key] = summary["by_classification"].get(key, 0) + 1
    with kernel.store.transaction():
        kernel.store.execute(
            "INSERT INTO reconciliation_runs (run_id, environment, source_sha, started_at, finished_at, status, "
            "mutation_lock_held, summary_json) VALUES (?,?,?,?,?,?,?,?)",
            (run_id, environment, str(plan.get("planSourceSha", "")), utc(now), utc(now), status,
             "" if consistent else f"{lease_state_before}|{lease_state_after}", canonical_json(summary)))
        for finding in findings:
            kernel.store.execute(
                "INSERT INTO drift_findings (finding_id, run_id, resource_kind, resource_name, classification, "
                "severity, detail_json, detected_at) VALUES (?,?,?,?,?,?,?,?)",
                (new_id("dft"), run_id, finding["resource_kind"], finding["resource_name"],
                 finding["classification"], finding["severity"], canonical_json(finding["detail"]), utc(now)))
    return {"run_id": run_id, "environment": environment, "status": status, **summary}

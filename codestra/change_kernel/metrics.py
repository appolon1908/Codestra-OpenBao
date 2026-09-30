"""Prometheus textfile rendering for the openbao_v3_* metric family.

Labels are bounded to environment, status, risk class, drift classification
and denial kind. No path, identity, token or payload ever becomes a label.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

from .kernel import ChangeKernel

ALLOWED_LABELS = frozenset({"environment", "status", "risk_class", "classification", "kind"})


def _line(name: str, value: float, labels: dict[str, str] | None = None) -> str:
    labels = labels or {}
    unknown = set(labels) - ALLOWED_LABELS
    if unknown:
        raise ValueError(f"unbounded_metric_label:{sorted(unknown)}")
    rendered = ",".join(f'{key}="{str(val).replace(chr(34), "")}"' for key, val in sorted(labels.items()))
    return f"{name}{{{rendered}}} {value:g}" if rendered else f"{name} {value:g}"


def render(kernel: ChangeKernel, environment: str, *, backup_evidence: Path | None = None,
           restore_evidence: Path | None = None, cluster_status: dict[str, Any] | None = None) -> str:
    store = kernel.store
    now = kernel.clock()
    out: list[str] = []

    def family(name: str, kind: str, text: str) -> None:
        out.append(f"# HELP {name} {text}")
        out.append(f"# TYPE {name} {kind}")

    family("openbao_v3_changes_total", "counter", "Change requests by status and risk class.")
    for row in store.all("SELECT status, risk_class, COUNT(*) AS n FROM change_requests WHERE environment = ? "
                         "GROUP BY status, risk_class", (environment,)):
        out.append(_line("openbao_v3_changes_total", row["n"],
                         {"environment": environment, "status": row["status"], "risk_class": row["risk_class"]}))
    family("openbao_v3_change_failures_total", "counter", "Changes that failed, need reconciliation or dead-lettered.")
    failures = store.one("SELECT COUNT(*) AS n FROM change_requests WHERE environment = ? AND status IN "
                         "('RETRY','RECONCILIATION_REQUIRED','DEAD_LETTER')", (environment,))
    out.append(_line("openbao_v3_change_failures_total", failures["n"], {"environment": environment}))
    for metric, kinds in (("openbao_v3_policy_denials_total", ("POLICY_DENIED",)),
                          ("openbao_v3_safety_denials_total", ("SAFETY_DENIED", "LOCK_DENIED"))):
        family(metric, "counter", "Refused kernel requests.")
        count = store.one(f"SELECT COUNT(*) AS n FROM events WHERE event_type IN ({','.join('?' * len(kinds))})",
                          kinds)
        out.append(_line(metric, count["n"], {"environment": environment}))
    family("openbao_v3_reconciliation_total", "counter", "Reconciliation runs by result.")
    for row in store.all("SELECT status, COUNT(*) AS n FROM reconciliation_runs WHERE environment = ? "
                         "GROUP BY status", (environment,)):
        out.append(_line("openbao_v3_reconciliation_total", row["n"], {"environment": environment, "status": row["status"]}))
    family("openbao_v3_drift_total", "gauge", "Findings of the latest consistent reconciliation run.")
    latest = store.one("SELECT run_id FROM reconciliation_runs WHERE environment = ? AND status != 'INCONSISTENT' "
                       "ORDER BY started_at DESC", (environment,))
    if latest:
        for row in store.all("SELECT classification, COUNT(*) AS n FROM drift_findings WHERE run_id = ? "
                             "GROUP BY classification", (latest["run_id"],)):
            out.append(_line("openbao_v3_drift_total", row["n"],
                             {"environment": environment, "classification": row["classification"]}))
    family("openbao_v3_outbox_pending", "gauge", "Outbox messages not yet delivered.")
    out.append(_line("openbao_v3_outbox_pending",
                      store.one("SELECT COUNT(*) AS n FROM outbox WHERE status = 'PENDING'")["n"]))
    family("openbao_v3_worker_leases", "gauge", "Unexpired mutation leases for this environment.")
    lock = kernel.lock_status(environment)
    out.append(_line("openbao_v3_worker_leases", 1 if lock and not lock["expired"] else 0, {"environment": environment}))
    if backup_evidence is not None:
        data = json.loads(backup_evidence.read_text(encoding="utf-8"))
        completed = dt.datetime.fromisoformat(str(data["completedAt"]).replace("Z", "+00:00"))
        family("openbao_v3_backup_age_seconds", "gauge", "Age of the latest verified off-host backup.")
        age = (now - completed).total_seconds() if data.get("backup") == "PASS" else float("inf")
        out.append(_line("openbao_v3_backup_age_seconds", age, {"environment": environment}))
    if restore_evidence is not None:
        data = json.loads(restore_evidence.read_text(encoding="utf-8"))
        family("openbao_v3_restore_last_success", "gauge", "1 when the latest isolated restore passed its RTO.")
        passed = data.get("restore") == "PASS" and data.get("rtoMet") is True
        out.append(_line("openbao_v3_restore_last_success", 1 if passed else 0, {"environment": environment}))
    if cluster_status is not None:
        family("openbao_v3_cluster_voters", "gauge", "Current Raft voters.")
        out.append(_line("openbao_v3_cluster_voters", int(cluster_status["voters"]), {"environment": environment}))
        family("openbao_v3_cluster_sealed", "gauge", "1 when sealed or seal state is unknown.")
        out.append(_line("openbao_v3_cluster_sealed", 0 if cluster_status.get("sealed") is False else 1,
                         {"environment": environment}))
    return "\n".join(out) + "\n"

#!/usr/bin/env python3
"""Verify the replay plugin SBOM identity and zero-HIGH/CRITICAL scan.

The plugin has no VEX, so any HIGH, CRITICAL or unscored (UNKNOWN) finding fails, a
missing or unrecognised severity fails closed, and the scan must be current by its own
machine-readable CreatedAt timestamp.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "plugins/codestra-jwt-replay/plugin.v1.json"
SBOM = ROOT / "artifacts/supply-chain/codestra-jwt-replay-v1.1.0-linux-amd64.cdx.json"
REPORT = ROOT / "artifacts/supply-chain/codestra-jwt-replay-v1.1.0-linux-amd64.trivy.json"
GATED_SEVERITIES = {"HIGH", "CRITICAL", "UNKNOWN"}
KNOWN_SEVERITIES = GATED_SEVERITIES | {"LOW", "MEDIUM"}
MAX_SCAN_AGE = dt.timedelta(days=30)
MAX_CLOCK_SKEW = dt.timedelta(minutes=10)


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"not_an_object:{path.name}")
    return value


def packages(sbom: dict) -> dict[str, str]:
    return {
        str(item.get("name")): str(item.get("version"))
        for item in sbom.get("components", [])
        if item.get("type") == "library"
    }


def require_current_scan(report: dict, now: dt.datetime) -> None:
    created_at = report.get("CreatedAt")
    if not isinstance(created_at, str) or not created_at:
        raise ValueError("plugin_scan_created_at_missing")
    try:
        created = dt.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("plugin_scan_created_at_invalid") from exc
    if created.tzinfo is None:
        raise ValueError("plugin_scan_created_at_not_timezone_aware")
    if created > now + MAX_CLOCK_SKEW:
        raise ValueError("plugin_scan_created_in_future")
    if now - created > MAX_SCAN_AGE:
        raise ValueError(
            f"plugin_scan_stale:scanned={created.date().isoformat()}:max_age_days={MAX_SCAN_AGE.days}"
        )


def validate(sbom_path: Path, report_path: Path, now: dt.datetime | None = None) -> tuple[int, int]:
    now = now or dt.datetime.now(dt.timezone.utc)
    manifest = load(MANIFEST)
    sbom = load(sbom_path)
    report = load(report_path)
    digest = manifest["binarySha256"]
    component = (sbom.get("metadata") or {}).get("component") or {}
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.7":
        raise ValueError("plugin_sbom_format_drift")
    if component.get("name") != manifest["name"] or component.get("version") != f"sha256:{digest}":
        raise ValueError("plugin_sbom_identity_drift")
    tools = ((sbom.get("metadata") or {}).get("tools") or {}).get("components", [])
    if not any(item.get("name") == "syft" and item.get("version") == "1.51.1" for item in tools):
        raise ValueError("plugin_sbom_generator_drift")
    inventory = packages(sbom)
    if len(inventory) < 50:
        raise ValueError("plugin_sbom_inventory_incomplete")
    if inventory.get("stdlib") != "go" + manifest["goVersion"]:
        raise ValueError("plugin_go_toolchain_drift")
    overrides = manifest["securityDependencyOverrides"]
    if not isinstance(overrides, list) or not overrides:
        raise ValueError("plugin_security_overrides_missing")
    seen_overrides: set[str] = set()
    for override in overrides:
        module = override["module"]
        if module in seen_overrides:
            raise ValueError(f"plugin_security_override_duplicate:{module}")
        seen_overrides.add(module)
        if inventory.get(module) != override["version"]:
            raise ValueError(f"plugin_security_override_missing:{module}")
    for module, version in manifest["resolvedSecurityModules"].items():
        if module in inventory and inventory[module] != version:
            raise ValueError(f"plugin_module_drift:{module}")

    require_current_scan(report, now)
    results = report.get("Results")
    if not isinstance(results, list):
        raise ValueError("plugin_report_results_missing")
    unresolved: list[str] = []
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("plugin_report_result_invalid")
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            continue
        if not isinstance(vulnerabilities, list):
            raise ValueError("plugin_report_vulnerabilities_invalid")
        for finding in vulnerabilities:
            if not isinstance(finding, dict):
                raise ValueError("plugin_report_finding_invalid")
            severity = finding.get("Severity")
            vulnerability_id = finding.get("VulnerabilityID")
            package_name = finding.get("PkgName")
            if not isinstance(vulnerability_id, str) or not vulnerability_id.strip():
                raise ValueError("plugin_finding_vulnerability_id_missing")
            if not isinstance(package_name, str) or not package_name.strip():
                raise ValueError(f"plugin_finding_package_missing:{vulnerability_id}")
            identity = f"{vulnerability_id}:{package_name}"
            if severity not in KNOWN_SEVERITIES:
                raise ValueError(f"plugin_unrecognized_severity:{identity}:{severity!r}")
            if severity in GATED_SEVERITIES:
                unresolved.append(f"{identity}:{severity}")
    if unresolved:
        raise ValueError(
            f"plugin_unresolved_high_critical:{len(unresolved)}:" + ",".join(sorted(unresolved))
        )
    return len(inventory), 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sbom", type=Path, default=SBOM)
    parser.add_argument("--report", type=Path, default=REPORT)
    args = parser.parse_args()
    try:
        component_count, observations = validate(args.sbom, args.report)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"OPENBAO_PLUGIN_SUPPLY_CHAIN=FAIL ERROR={exc}") from exc
    print("OPENBAO_PLUGIN_SUPPLY_CHAIN=PASS")
    print(f"PLUGIN_SBOM_COMPONENT_COUNT={component_count}")
    print(f"PLUGIN_HIGH_CRITICAL_OBSERVATIONS={observations}")
    print("PLUGIN_UNRESOLVED_HIGH_CRITICAL=0")


if __name__ == "__main__":
    main()

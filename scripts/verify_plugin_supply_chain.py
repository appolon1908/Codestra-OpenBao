#!/usr/bin/env python3
"""Verify the replay plugin SBOM, rebuilt binary identity, and vulnerability scan.

The plugin has no VEX. HIGH, CRITICAL, and UNKNOWN findings fail closed. The
validator binds evidence to the exact rebuilt binary when --plugin is supplied,
and binds a rootfs scan to its exact scan root when --scan-root is supplied.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import posixpath
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
    components = sbom.get("components")
    if not isinstance(components, list):
        raise ValueError("plugin_sbom_components_missing")
    return {
        str(item.get("name")): str(item.get("version"))
        for item in components
        if isinstance(item, dict) and item.get("type") == "library"
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_scan_path(value: str | Path) -> str:
    """Normalize POSIX/Windows evidence paths without consulting the local OS."""
    text = str(value).strip()
    if not text:
        raise ValueError("plugin_scan_path_empty")
    normalized = posixpath.normpath(text.replace("\\", "/"))
    if len(normalized) >= 2 and normalized[1] == ":":
        normalized = normalized[0].lower() + normalized[1:]
    return normalized


def scan_basename(value: str | Path) -> str:
    return posixpath.basename(normalize_scan_path(value).rstrip("/"))


def is_absolute_scan_path(value: str | Path) -> bool:
    normalized = normalize_scan_path(value)
    return normalized.startswith("/") or (len(normalized) >= 3 and normalized[1:3] == ":/")


def require_plugin_binary(plugin_path: Path, manifest: dict) -> None:
    if not plugin_path.is_file():
        raise ValueError(f"plugin_binary_missing:{plugin_path}")
    if scan_basename(plugin_path) != manifest.get("command"):
        raise ValueError("plugin_binary_name_drift")
    actual = sha256_file(plugin_path)
    expected = manifest.get("binarySha256")
    if not isinstance(expected, str) or len(expected) != 64:
        raise ValueError("plugin_manifest_binary_digest_invalid")
    if actual != expected:
        raise ValueError(f"plugin_binary_digest_drift:expected={expected}:actual={actual}")


def require_report_scan_binding(report: dict, manifest: dict, scan_root: str | Path | None) -> None:
    if report.get("SchemaVersion") != 2:
        raise ValueError("plugin_report_schema_drift")
    if report.get("ArtifactType") != "filesystem":
        raise ValueError("plugin_report_artifact_type_drift")
    artifact_name = report.get("ArtifactName")
    if not isinstance(artifact_name, str) or not artifact_name.strip():
        raise ValueError("plugin_report_artifact_name_missing")

    if scan_root is None:
        # Historical committed evidence scanned the exact binary path.
        if scan_basename(artifact_name) != manifest.get("command"):
            raise ValueError("plugin_report_artifact_drift")
    else:
        actual_root = normalize_scan_path(artifact_name)
        expected_root = normalize_scan_path(scan_root)
        if actual_root != expected_root:
            raise ValueError(
                f"plugin_report_scan_root_drift:expected={expected_root}:actual={actual_root}"
            )

    results = report.get("Results")
    if not isinstance(results, list):
        raise ValueError("plugin_report_results_missing")
    binary_seen = False
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("plugin_report_result_invalid")
        if result.get("Type") != "gobinary":
            continue
        target = result.get("Target")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("plugin_report_binary_target_missing")
        normalized_target = normalize_scan_path(target)
        if normalized_target == ".." or normalized_target.startswith("../"):
            raise ValueError("plugin_report_binary_target_escape")
        if scan_basename(normalized_target) != manifest.get("command"):
            continue
        if scan_root is not None and is_absolute_scan_path(normalized_target):
            expected_binary = normalize_scan_path(scan_root).rstrip("/") + "/" + str(
                manifest.get("command")
            )
            if normalized_target != expected_binary:
                raise ValueError("plugin_report_binary_outside_scan_root")
        binary_seen = True
    if not binary_seen:
        raise ValueError("plugin_report_binary_not_scanned")


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
    created = created.astimezone(dt.timezone.utc)
    now = now.astimezone(dt.timezone.utc)
    if created > now + MAX_CLOCK_SKEW:
        raise ValueError("plugin_scan_created_in_future")
    if now - created > MAX_SCAN_AGE:
        raise ValueError(
            f"plugin_scan_stale:scanned={created.date().isoformat()}:max_age_days={MAX_SCAN_AGE.days}"
        )


def validate(
    sbom_path: Path,
    report_path: Path,
    now: dt.datetime | None = None,
    *,
    plugin_path: Path | None = None,
    scan_root: str | Path | None = None,
) -> tuple[int, int]:
    now = now or dt.datetime.now(dt.timezone.utc)
    manifest = load(MANIFEST)
    sbom = load(sbom_path)
    report = load(report_path)

    if plugin_path is not None:
        require_plugin_binary(plugin_path, manifest)
        if scan_root is not None:
            expected_plugin = normalize_scan_path(scan_root).rstrip("/") + "/" + str(
                manifest.get("command")
            )
            actual_plugin = normalize_scan_path(plugin_path)
            if actual_plugin != expected_plugin:
                raise ValueError(
                    f"plugin_path_outside_scan_root:expected={expected_plugin}:actual={actual_plugin}"
                )

    digest = manifest["binarySha256"]
    component = (sbom.get("metadata") or {}).get("component") or {}
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.7":
        raise ValueError("plugin_sbom_format_drift")
    if component.get("name") != manifest["name"] or component.get("version") != f"sha256:{digest}":
        raise ValueError("plugin_sbom_identity_drift")
    tools = ((sbom.get("metadata") or {}).get("tools") or {}).get("components", [])
    if not any(
        isinstance(item, dict) and item.get("name") == "syft" and item.get("version") == "1.51.1"
        for item in tools
    ):
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
        if not isinstance(override, dict):
            raise ValueError("plugin_security_override_invalid")
        module = override.get("module")
        version = override.get("version")
        if not isinstance(module, str) or not module:
            raise ValueError("plugin_security_override_module_missing")
        if module in seen_overrides:
            raise ValueError(f"plugin_security_override_duplicate:{module}")
        seen_overrides.add(module)
        if inventory.get(module) != version:
            raise ValueError(f"plugin_security_override_missing:{module}")
    resolved_modules = manifest.get("resolvedSecurityModules")
    if not isinstance(resolved_modules, dict):
        raise ValueError("plugin_resolved_modules_missing")
    for module, version in resolved_modules.items():
        if module in inventory and inventory[module] != version:
            raise ValueError(f"plugin_module_drift:{module}")

    require_report_scan_binding(report, manifest, scan_root)
    require_current_scan(report, now)

    unresolved: list[str] = []
    for result in report["Results"]:
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
    parser.add_argument("--plugin", type=Path)
    parser.add_argument("--scan-root")
    args = parser.parse_args()
    try:
        component_count, observations = validate(
            args.sbom,
            args.report,
            plugin_path=args.plugin,
            scan_root=args.scan_root,
        )
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"OPENBAO_PLUGIN_SUPPLY_CHAIN=FAIL ERROR={exc}") from exc
    print("OPENBAO_PLUGIN_SUPPLY_CHAIN=PASS")
    print(f"PLUGIN_SBOM_COMPONENT_COUNT={component_count}")
    print(f"PLUGIN_HIGH_CRITICAL_OBSERVATIONS={observations}")
    print("PLUGIN_UNRESOLVED_HIGH_CRITICAL=0")


if __name__ == "__main__":
    main()

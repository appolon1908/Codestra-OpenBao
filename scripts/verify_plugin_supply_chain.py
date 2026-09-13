#!/usr/bin/env python3
"""Verify the replay plugin SBOM identity and zero-HIGH/CRITICAL scan."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "plugins/codestra-jwt-replay/plugin.v1.json"
SBOM = ROOT / "artifacts/supply-chain/codestra-jwt-replay-v1.1.0-linux-amd64.cdx.json"
REPORT = ROOT / "artifacts/supply-chain/codestra-jwt-replay-v1.1.0-linux-amd64.trivy.json"


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


def validate(sbom_path: Path, report_path: Path) -> tuple[int, int]:
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

    observations = 0
    unresolved = 0
    for result in report.get("Results", []):
        for finding in result.get("Vulnerabilities") or []:
            if finding.get("Severity") in {"HIGH", "CRITICAL"}:
                observations += 1
                unresolved += 1
    if unresolved:
        raise ValueError(f"plugin_unresolved_high_critical:{unresolved}")
    return len(inventory), observations


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

#!/usr/bin/env python3
"""Verify a freshly generated CycloneDX inventory against committed authority."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = ROOT / "artifacts/supply-chain/openbao-2.6.2-linux-amd64.cdx.json"
EXPECTED_NAME = "ghcr.io/openbao/openbao"
EXPECTED_DIGEST = "sha256:e29524ba7c3f20d01f562c481e3eccbad6c91df45a2f2531433da4951e408cff"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("SBOM must be a JSON object")
    return value


def inventory(document: dict) -> list[tuple]:
    result = []
    for component in document.get("components", []):
        hashes = tuple(
            sorted(
                (str(item.get("alg")), str(item.get("content")))
                for item in component.get("hashes", [])
            )
        )
        result.append(
            (
                str(component.get("type", "")),
                str(component.get("group", "")),
                str(component.get("name", "")),
                str(component.get("version", "")),
                str(component.get("purl", "")),
                hashes,
            )
        )
    return sorted(result)


def dependency_inventory(document: dict) -> list[tuple[str, tuple[str, ...]]]:
    return sorted(
        (str(item.get("ref", "")), tuple(sorted(map(str, item.get("dependsOn", [])))))
        for item in document.get("dependencies", [])
    )


def validate(document: dict) -> None:
    if document.get("bomFormat") != "CycloneDX":
        raise ValueError("SBOM format drift")
    component = (document.get("metadata") or {}).get("component") or {}
    if component.get("name") != EXPECTED_NAME or component.get("version") != EXPECTED_DIGEST:
        raise ValueError("SBOM image identity drift")
    tools = ((document.get("metadata") or {}).get("tools") or {}).get("components", [])
    if not any(item.get("name") == "syft" and item.get("version") == "1.51.1" for item in tools):
        raise ValueError("SBOM generator identity drift")
    if len(document.get("components", [])) < 1000:
        raise ValueError("SBOM component inventory unexpectedly small")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True, type=Path)
    args = parser.parse_args()
    try:
        authority = load(AUTHORITY)
        candidate = load(args.candidate)
        validate(authority)
        validate(candidate)
        if inventory(candidate) != inventory(authority):
            raise ValueError("SBOM package inventory drift")
        if dependency_inventory(candidate) != dependency_inventory(authority):
            raise ValueError("SBOM dependency inventory drift")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"OPENBAO_SBOM=FAIL ERROR={exc}") from exc
    print("OPENBAO_SBOM=PASS")
    print(f"SBOM_COMPONENT_COUNT={len(candidate['components'])}")
    print("SBOM_IMAGE_DIGEST_MATCH=PASS")


if __name__ == "__main__":
    main()

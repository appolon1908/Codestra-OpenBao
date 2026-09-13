#!/usr/bin/env python3
"""Fail-closed validation for the Codestra OpenBao Orbit consumer contract."""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, NoReturn, Sequence

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "orbit/adoption-manifest.json"
SCHEMA_PATH = ROOT / "orbit/adoption-manifest.schema.json"

EXPECTED_SCHEMA_VERSION = "2.0.0"
EXPECTED_REPOSITORY = "appolon1908-hue/Codestra-OpenBao"
EXPECTED_CLASSIFICATION = "vendor-operator-ui"
EXPECTED_TARGET_BRANCH = "codex/codestra-orbit-v2-codestra-openbao"
EXPECTED_ADOPTION_MODE = "operator-theme-sso"
EXPECTED_DOMAIN = "bao.codestra.media"
EXPECTED_DOMAIN_STATUS = "verification-required"
EXPECTED_STATUS = "blocked"

REQUIRED_TOP_LEVEL = frozenset(
    {
        "schemaVersion",
        "repository",
        "classification",
        "targetBranch",
        "adoptionMode",
        "requirements",
        "status",
    }
)
OPTIONAL_TOP_LEVEL = frozenset({"domain", "domainStatus", "blockers"})
ALLOWED_TOP_LEVEL = REQUIRED_TOP_LEVEL | OPTIONAL_TOP_LEVEL

EXPECTED_CLASSIFICATIONS = frozenset(
    {
        "source-authority",
        "first-party-ui",
        "vendor-operator-ui",
        "backend-api",
        "runtime-infrastructure",
        "observability-backend",
        "documentation",
        "inventory-required",
    }
)
EXPECTED_ADOPTION_MODES = frozenset(
    {
        "package-authority",
        "full-shell",
        "operator-theme-sso",
        "contract-only",
        "n/a-no-rendered-interface",
        "inventory-required",
    }
)
EXPECTED_DOMAIN_STATUSES = frozenset(
    {
        "registered",
        "verification-required",
        "pending-registration",
        "not-applicable",
    }
)
EXPECTED_STATUSES = frozenset(
    {
        "not-started",
        "branch-created",
        "implementation-in-progress",
        "blocked",
        "candidate",
        "certified",
    }
)
TARGET_BRANCH_PATTERN = r"^codex/codestra-orbit-v2-[a-z0-9-]+$"
REPOSITORY_PATTERN = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
DOMAIN_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)

EXPECTED_REQUIREMENTS = {
    "renderedInterface": True,
    "loginLogoutRequired": True,
    "sharedHeaderFooterRequired": False,
    "approvedIdentitySSORequired": True,
    "nativeAuthenticationFallbackRequired": True,
    "logoutRequired": True,
    "logoutAllRequired": True,
    "sessionRevocationRequired": True,
    "browserTokenStorageProhibited": True,
    "supportedThemeOnly": True,
    "nativeBehaviorPreserved": True,
    "secretValuesInBrowserApisProhibited": True,
    "nativePortsPublic": False,
    "runtimeApplyAuthorized": False,
    "productionCertified": False,
}

REQUIRED_BLOCKER_FRAGMENTS = (
    "sdk-repository pr #75",
    "independent approval",
    "repository catalog",
    "dns",
    "tls",
    "logout-all",
    "least privilege",
    "rollback",
    "runtime",
    "protected promotion",
)


class OrbitAdoptionValidationError(ValueError):
    """Raised when the consumer contract is incomplete or unsafe."""


def _fail(message: str) -> NoReturn:
    raise OrbitAdoptionValidationError(message)


def _read_json(path: Path, *, label: str) -> Any:
    if not path.is_file() or path.is_symlink():
        _fail(f"{label} must be a regular file")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"{label} is not valid UTF-8 JSON: {exc}")


def _string(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{field} must be a non-empty string")
    return value


def _property(document: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    properties = document.get("properties")
    if not isinstance(properties, Mapping):
        _fail("schema properties must be an object")
    value = properties.get(name)
    if not isinstance(value, Mapping):
        _fail(f"schema property missing or invalid: {name}")
    return value


def _string_set(value: Any, *, field: str) -> frozenset[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        _fail(f"{field} must be an array of strings")
    if len(value) != len(set(value)):
        _fail(f"{field} must not contain duplicates")
    return frozenset(value)


def validate_schema(schema: Any) -> None:
    if not isinstance(schema, Mapping):
        _fail("schema must be an object")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        _fail("schema draft must remain 2020-12")
    if schema.get("$id") != "https://schemas.codestra.co/orbit/v2/adoption-manifest.schema.json":
        _fail("schema identifier drift")
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        _fail("schema must be a closed object")
    if _string_set(schema.get("required"), field="schema required") != REQUIRED_TOP_LEVEL:
        _fail("schema required fields drift")
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        _fail("schema properties must be an object")
    if frozenset(properties) != ALLOWED_TOP_LEVEL:
        _fail("schema property names drift")

    if _property(schema, "schemaVersion").get("const") != EXPECTED_SCHEMA_VERSION:
        _fail("schema version drift")
    if _property(schema, "repository").get("pattern") != REPOSITORY_PATTERN:
        _fail("repository pattern drift")
    if _property(schema, "targetBranch").get("pattern") != TARGET_BRANCH_PATTERN:
        _fail("target-branch pattern drift")
    if _string_set(
        _property(schema, "classification").get("enum"),
        field="classification enum",
    ) != EXPECTED_CLASSIFICATIONS:
        _fail("classification enum drift")
    if _string_set(
        _property(schema, "adoptionMode").get("enum"),
        field="adoption mode enum",
    ) != EXPECTED_ADOPTION_MODES:
        _fail("adoption-mode enum drift")
    if _string_set(
        _property(schema, "domainStatus").get("enum"),
        field="domain status enum",
    ) != EXPECTED_DOMAIN_STATUSES:
        _fail("domain-status enum drift")
    if _string_set(
        _property(schema, "status").get("enum"),
        field="status enum",
    ) != EXPECTED_STATUSES:
        _fail("status enum drift")

    requirements = _property(schema, "requirements")
    additional = requirements.get("additionalProperties")
    if requirements.get("type") != "object" or additional != {"type": "boolean"}:
        _fail("requirements schema must admit boolean flags only")

    blockers = _property(schema, "blockers")
    if blockers.get("type") != "array" or blockers.get("items") != {"type": "string"}:
        _fail("blockers schema drift")


def validate_manifest(document: Any) -> None:
    if not isinstance(document, Mapping):
        _fail("manifest must be an object")

    keys = frozenset(document)
    missing = REQUIRED_TOP_LEVEL - keys
    extra = keys - ALLOWED_TOP_LEVEL
    if missing:
        _fail(f"manifest required fields missing: {sorted(missing)}")
    if extra:
        _fail(f"manifest contains unsupported fields: {sorted(extra)}")

    exact_fields = {
        "schemaVersion": EXPECTED_SCHEMA_VERSION,
        "repository": EXPECTED_REPOSITORY,
        "classification": EXPECTED_CLASSIFICATION,
        "targetBranch": EXPECTED_TARGET_BRANCH,
        "adoptionMode": EXPECTED_ADOPTION_MODE,
        "domain": EXPECTED_DOMAIN,
        "domainStatus": EXPECTED_DOMAIN_STATUS,
        "status": EXPECTED_STATUS,
    }
    for field, expected in exact_fields.items():
        if document.get(field) != expected:
            _fail(f"{field} must remain {expected!r}")

    repository = _string(document["repository"], field="repository")
    if re.fullmatch(REPOSITORY_PATTERN, repository) is None:
        _fail("repository syntax invalid")
    target = _string(document["targetBranch"], field="targetBranch")
    if re.fullmatch(TARGET_BRANCH_PATTERN, target) is None:
        _fail("target branch syntax invalid")
    domain = _string(document["domain"], field="domain")
    if DOMAIN_PATTERN.fullmatch(domain) is None:
        _fail("domain must be a hostname without scheme, path or port")

    requirements = document.get("requirements")
    if not isinstance(requirements, Mapping):
        _fail("requirements must be an object")
    if any(type(value) is not bool for value in requirements.values()):
        _fail("every requirement must be boolean")
    if dict(requirements) != EXPECTED_REQUIREMENTS:
        _fail("OpenBao-specific requirement set drift")

    blockers = document.get("blockers")
    if not isinstance(blockers, list) or not blockers:
        _fail("blocked adoption requires explicit blockers")
    if any(
        not isinstance(item, str)
        or len(item.strip()) < 20
        or len(item) > 500
        or "\n" in item
        for item in blockers
    ):
        _fail("every blocker must be a bounded single-line string")
    normalized = [item.strip() for item in blockers]
    if len(normalized) != len(set(normalized)):
        _fail("blockers must be unique")
    blocker_text = " ".join(normalized).casefold()
    missing_fragments = [
        fragment for fragment in REQUIRED_BLOCKER_FRAGMENTS if fragment not in blocker_text
    ]
    if missing_fragments:
        _fail(f"required blocker coverage missing: {missing_fragments}")

    if requirements["runtimeApplyAuthorized"] is not False:
        _fail("Orbit adoption must not authorize runtime application")
    if requirements["productionCertified"] is not False:
        _fail("Orbit adoption must not claim production certification")
    if requirements["nativePortsPublic"] is not False:
        _fail("native OpenBao ports must remain private")
    if requirements["browserTokenStorageProhibited"] is not True:
        _fail("browser token storage must remain prohibited")
    if requirements["secretValuesInBrowserApisProhibited"] is not True:
        _fail("secret values must remain outside browser APIs")
    if requirements["nativeBehaviorPreserved"] is not True:
        _fail("native OpenBao behavior must be preserved")
    if requirements["nativeAuthenticationFallbackRequired"] is not True:
        _fail("native authentication fallback must remain required")
    if requirements["sharedHeaderFooterRequired"] is not False:
        _fail("vendor operator UI must not require an invasive shared shell")


def validate_files(
    manifest_path: Path = MANIFEST_PATH,
    schema_path: Path = SCHEMA_PATH,
) -> None:
    schema = _read_json(schema_path, label="Orbit adoption schema")
    manifest = _read_json(manifest_path, label="Orbit adoption manifest")
    validate_schema(schema)
    validate_manifest(manifest)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        if argv:
            _fail("this validator does not accept command-line arguments")
        validate_files()
    except OrbitAdoptionValidationError as exc:
        print(f"OPENBAO_ORBIT_ADOPTION=FAIL ERROR={exc}")
        return 1
    print("OPENBAO_ORBIT_ADOPTION=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

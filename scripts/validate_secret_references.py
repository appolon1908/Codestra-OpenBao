#!/usr/bin/env python3
"""Fail-closed validation of the secret-reference contract and catalog.

A secret reference points at a secret that only OpenBao holds. This validator
proves that every reviewed reference is a pointer (never a value), belongs to
its own environment, lies beneath a path prefix admitted to the named workload
identity and never names a forbidden key. It is stdlib-only so it runs in every
consumer repository that vendors the schema.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts/secret-reference.v1.schema.json"
CATALOG = ROOT / "config/secret-references.v1.json"
AUTHORITY = ROOT / "config/workload-secret-authority.v1.json"

ENVIRONMENTS = ("development", "test", "staging", "production")
FORBIDDEN_KEYS = frozenset(
    {
        "value", "password", "token", "private_key", "client_secret", "secret",
        "secret_value", "unseal_key", "recovery_key", "root_token",
    }
)
# Secret-shaped values: OpenBao/Vault tokens, PEM blocks, long opaque credentials.
SECRET_SHAPED = re.compile(
    r"(hvs\.[A-Za-z0-9_-]{20,}|hvb\.[A-Za-z0-9_-]{20,}|\bs\.[A-Za-z0-9]{24,}\b|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,})"
)
SECRET_REF = re.compile(
    r"^codestra/(development|test|staging|production)/[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)+$"
)
SERVICE_ID = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
IDENTITY = re.compile(r"^[a-z][a-z0-9-]+$")
REPOSITORY = re.compile(r"^appolon1908-hue/[A-Za-z0-9._-]+$")
URI = "openbao://"


class ContractError(ValueError):
    pass


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _walk(value, trail: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in FORBIDDEN_KEYS or key.lower().endswith(("_password", "_token", "_secret")):
                errors.append(f"{trail}: forbidden key {key!r}")
            _walk(item, f"{trail}.{key}", errors)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk(item, f"{trail}[{index}]", errors)
    elif isinstance(value, str) and SECRET_SHAPED.search(value):
        errors.append(f"{trail}: secret-shaped value")


def admitted_prefixes(authority: dict) -> dict[tuple[str, str], list[str]]:
    prefixes: dict[tuple[str, str], list[str]] = {}
    for role in authority["roles"]:
        prefixes[(role["environment"], role["serviceIdentity"])] = list(role["pathPrefixes"])
    return prefixes


def validate_reference(reference: dict, schema: dict, prefixes: dict[tuple[str, str], list[str]], trail: str) -> list[str]:
    errors: list[str] = []
    allowed = set(schema["properties"]) | {"purpose"}
    if not isinstance(reference, dict):
        return [f"{trail}: reference must be an object"]
    unknown = sorted(set(reference) - allowed)
    if unknown:
        errors.append(f"{trail}: unknown properties {unknown}")
    for required in schema["required"]:
        if required not in reference:
            errors.append(f"{trail}: missing {required}")
    _walk(reference, trail, errors)
    if errors:
        return errors
    environment = reference["environment"]
    ref = reference["secret_ref"]
    if reference["provider"] != "openbao":
        errors.append(f"{trail}: provider must be openbao")
    if environment not in ENVIRONMENTS:
        errors.append(f"{trail}: unknown environment {environment!r}")
    if not isinstance(ref, str) or not SECRET_REF.fullmatch(ref) or "*" in ref or ".." in ref or "//" in ref:
        errors.append(f"{trail}: malformed secret_ref {ref!r}")
    elif not ref.startswith(f"codestra/{environment}/"):
        errors.append(f"{trail}: secret_ref {ref!r} is outside environment {environment}")
    if not SERVICE_ID.fullmatch(str(reference["service_id"])):
        errors.append(f"{trail}: malformed service_id")
    if reference["secret_class"] not in schema["properties"]["secret_class"]["enum"]:
        errors.append(f"{trail}: unknown secret_class {reference['secret_class']!r}")
    version = reference["version"]
    if version is not None and (type(version) is not int or version < 1):
        errors.append(f"{trail}: version must be null or a positive integer")
    uri = reference.get("reference_uri")
    if uri is not None and uri != URI + ref:
        errors.append(f"{trail}: reference_uri must equal openbao:// + secret_ref")
    repository = reference.get("consumer_repository")
    if repository is not None and not REPOSITORY.fullmatch(repository):
        errors.append(f"{trail}: consumer_repository must be a governed repository")
    identity = reference.get("workload_identity")
    if identity is not None:
        if not IDENTITY.fullmatch(identity):
            errors.append(f"{trail}: malformed workload_identity")
        else:
            admitted = prefixes.get((environment, identity))
            if admitted is None:
                errors.append(f"{trail}: identity {identity!r} is not admitted in {environment}")
            elif not any(ref.startswith(prefix) and ref != prefix.rstrip("/") for prefix in admitted):
                errors.append(f"{trail}: {ref!r} is outside the prefixes admitted to {identity!r}")
    status = reference.get("rotation_status")
    if status is not None and status not in schema["properties"]["rotation_status"]["enum"]:
        errors.append(f"{trail}: unknown rotation_status")
    return errors


def validate_catalog(catalog: dict, schema: dict, authority: dict) -> list[str]:
    errors: list[str] = []
    if catalog.get("secretValuesIncluded") is not False:
        errors.append("catalog must declare secretValuesIncluded=false")
    if catalog.get("runtimeApplyAuthorized") is not False:
        errors.append("catalog must not authorize runtime apply")
    if catalog.get("schema") != "contracts/secret-reference.v1.schema.json":
        errors.append("catalog must bind the v1 schema")
    references = catalog.get("references")
    if not isinstance(references, list) or not references:
        return errors + ["catalog references missing"]
    prefixes = admitted_prefixes(authority)
    seen: set[tuple[str, str, str]] = set()
    for index, reference in enumerate(references):
        trail = f"references[{index}]"
        errors.extend(validate_reference(reference, schema, prefixes, trail))
        if isinstance(reference, dict) and {"environment", "secret_ref", "workload_identity"} <= set(reference):
            key = (reference["environment"], reference["secret_ref"], reference["workload_identity"])
            if key in seen:
                errors.append(f"{trail}: duplicate reference")
            seen.add(key)
    return errors


def main() -> int:
    schema = load(SCHEMA)
    catalog = load(CATALOG)
    authority = load(AUTHORITY)
    if set(schema.get("x-codestra-forbidden-keys", [])) != FORBIDDEN_KEYS:
        print("SECRET_REFERENCE_CONTRACT=FAIL schema forbidden-key list drifted")
        return 1
    errors = validate_catalog(catalog, schema, authority)
    if errors:
        for error in errors:
            print(f"SECRET_REFERENCE_CONTRACT=FAIL {error}")
        return 1
    identities = sorted({r["workload_identity"] for r in catalog["references"]})
    print(f"SECRET_REFERENCE_CONTRACT=PASS references={len(catalog['references'])} identities={len(identities)}")
    print("SECRET_VALUES_IN_CATALOG=NONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())

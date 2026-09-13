#!/usr/bin/env python3
"""Validate OpenBao transport, workload-policy, and OIDC review boundaries."""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "codestra" / "runtime-v1" / "runtime.v1.json"
OIDC = ROOT / "codestra" / "runtime-v1" / "oidc-plan.v1.json"
CONFIG = ROOT / "codestra" / "runtime-v1" / "openbao.hcl.example"
WORKLOAD_POLICY = (
    ROOT / "codestra" / "runtime-v1" / "policies" / "workload-read-template.hcl"
)
PATH_RE = re.compile(r'^\s*path\s+"([^"]+)"\s*\{', re.MULTILINE)


def fail(message: str) -> None:
    print(f"OPENBAO_REVIEW_BOUNDARY_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: pathlib.Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot parse {path.relative_to(ROOT)}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain an object")
    return value


def main() -> None:
    try:
        config = CONFIG.read_text(encoding="utf-8")
        policy = WORKLOAD_POLICY.read_text(encoding="utf-8")
    except OSError as exc:
        fail(str(exc))

    required_transport = (
        'tls_disable = 0',
        'tls_min_version = "tls13"',
        'tls_require_and_verify_client_cert = true',
        'tls_disable_client_certs = false',
        'unauthenticated_metrics_access = false',
    )
    for fragment in required_transport:
        if fragment not in config:
            fail(f"OpenBao production transport is missing: {fragment}")
    forbidden_transport = (
        'tls_require_and_verify_client_cert = false',
        'tls_disable_client_certs = true',
        'tls_disable = 1',
        'unauthenticated_metrics_access = true',
    )
    for fragment in forbidden_transport:
        if fragment in config:
            fail(f"OpenBao production transport contains unsafe setting: {fragment}")

    paths = set(PATH_RE.findall(policy))
    for forbidden_path in (
        "sys/leases/renew",
        "sys/leases/revoke",
        "sys/leases/renew-prefix/*",
        "sys/leases/revoke-prefix/*",
        "sys/leases/revoke-force/*",
    ):
        if forbidden_path in paths:
            fail(f"ordinary workload policy may not grant {forbidden_path}")
    required_scoped_paths = {
        "kv-__BUSINESS__/data/__APPLICATION__/__ENVIRONMENT__/*",
        "kv-__BUSINESS__/metadata/__APPLICATION__/__ENVIRONMENT__/*",
        "database/creds/__DATABASE_ROLE__",
        "pki-platform-issuing/issue/__PKI_ROLE__",
        "transit-platform/encrypt/__TRANSIT_KEY__",
        "transit-platform/decrypt/__TRANSIT_KEY__",
    }
    missing = sorted(required_scoped_paths - paths)
    if missing:
        fail(f"ordinary workload policy lost required scoped paths: {missing}")

    runtime = load_json(RUNTIME)
    oidc = load_json(OIDC)
    runtime_client = runtime.get("identity", {}).get("human", {}).get("clientId")
    planned_client = oidc.get("client", {}).get("clientId")
    if runtime_client != "openbao-secrets":
        fail("runtime human OIDC client must be openbao-secrets")
    if planned_client != "openbao-secrets":
        fail("OIDC plan client must be openbao-secrets")
    if runtime_client != planned_client:
        fail("runtime and OIDC plan client IDs must match")

    transport = runtime.get("transport", {})
    if transport.get("tlsRequired") is not True:
        fail("runtime transport must require TLS")
    if transport.get("minimumVersion") != "TLS13":
        fail("runtime minimum TLS version must remain TLS13")
    if transport.get("plaintextListener") is not False:
        fail("runtime plaintext listener must remain disabled")
    if transport.get("publicNativePort") is not False:
        fail("runtime native port must remain private")

    activation = runtime.get("activation")
    if not isinstance(activation, dict) or not activation:
        fail("runtime activation map is missing")
    enabled = sorted(key for key, value in activation.items() if value is not False)
    if enabled:
        fail(f"runtime activation must remain false: {enabled}")

    print("CODESTRA_OPENBAO_REVIEW_BOUNDARY_VALIDATION_PASS=1")


if __name__ == "__main__":
    main()

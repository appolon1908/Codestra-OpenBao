#!/usr/bin/env python3
"""Render one least-privilege, file-only OpenBao Agent secret delivery bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = ROOT / "config/workload-secret-authority.v1.json"
AGENT_TEMPLATE = ROOT / "openbao/agent/agent.hcl.tpl"
SECRET_TEMPLATE = ROOT / "openbao/agent/secret.ctmpl.tpl"
ENVIRONMENTS = {"development", "test", "staging", "production"}
IDENTITY = re.compile(r"^[a-z][a-z0-9-]+$")


def checked_runtime_path(value: str, root: PurePosixPath) -> PurePosixPath:
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or not path.is_relative_to(root):
        raise ValueError("destination_outside_service_secret_root")
    if path == root or value.endswith("/"):
        raise ValueError("destination_must_be_a_file")
    return path


def render(
    environment: str,
    identity: str,
    logical_path: str,
    destination: str,
    service_uid: int,
    service_gid: int,
) -> dict[str, str]:
    if environment not in ENVIRONMENTS or not IDENTITY.fullmatch(identity):
        raise ValueError("invalid_identity_or_environment")
    if not 0 < service_uid < 2**31 or not 0 < service_gid < 2**31:
        raise ValueError("service_uid_gid_must_be_non_root")
    authority = json.loads(AUTHORITY.read_text(encoding="utf-8"))
    role = next(
        (
            item for item in authority["roles"]
            if item["environment"] == environment and item["serviceIdentity"] == identity
        ),
        None,
    )
    if role is None:
        raise ValueError("identity_not_authorized_for_environment")
    if (
        not isinstance(logical_path, str)
        or logical_path.endswith("/")
        or "*" in logical_path
        or "//" in logical_path
        or ".." in PurePosixPath(logical_path).parts
        or not any(logical_path.startswith(prefix) for prefix in role["pathPrefixes"])
    ):
        raise ValueError("secret_path_outside_role_authority")

    destination_path = checked_runtime_path(
        destination, PurePosixPath(f"/run/codestra-secrets/{identity}")
    )
    api_path = logical_path.replace("codestra/", "codestra/data/", 1)
    template_name = hashlib.sha256(logical_path.encode()).hexdigest()[:16] + ".ctmpl"
    installed_template = f"/etc/codestra/openbao-agent/{identity}/{template_name}"
    role_name = f"{identity}-{environment}"
    address = json.loads(
        (ROOT / f"config/environments/{environment}/environment.json").read_text(encoding="utf-8")
    )["canonicalApiAddress"]

    config = AGENT_TEMPLATE.read_text(encoding="utf-8")
    for marker, value in {
        "__OPENBAO_ADDRESS__": address,
        "__ROLE__": role_name,
        "__TEMPLATE_PATH__": installed_template,
        "__DESTINATION__": str(destination_path),
    }.items():
        config = config.replace(marker, value)
    secret_template = SECRET_TEMPLATE.read_text(encoding="utf-8").replace(
        "__SECRET_API_PATH__", api_path
    )
    if "__" in config or "__" in secret_template:
        raise ValueError("unresolved_template_marker")
    return {
        "agent.hcl": config,
        template_name: secret_template,
        "manifest.json": json.dumps(
            {
                "schemaVersion": 1,
                "environment": environment,
                "serviceIdentity": identity,
                "role": role_name,
                "logicalSecretPath": logical_path,
                "secretApiPath": api_path,
                "templateInstallPath": installed_template,
                "destination": str(destination_path),
                "fileMode": "0400",
                "requiredAgentUid": service_uid,
                "requiredAgentGid": service_gid,
                "destinationDirectoryPrecreatedAndOwnedByServiceRequired": True,
                "tokenSinkEnabled": False,
                "environmentInjectionEnabled": False,
                "providerBusinessEffectsEnabled": False,
                "secretValuesIncluded": False,
            },
            indent=2,
        ) + "\n",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", required=True, choices=sorted(ENVIRONMENTS))
    parser.add_argument("--identity", required=True)
    parser.add_argument("--secret-path", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--service-uid", required=True, type=int)
    parser.add_argument("--service-gid", required=True, type=int)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    if args.output_dir.exists():
        raise SystemExit("OPENBAO_AGENT_RENDER=FAIL ERROR=output_exists")
    try:
        bundle = render(
            args.environment,
            args.identity,
            args.secret_path,
            args.destination,
            args.service_uid,
            args.service_gid,
        )
        args.output_dir.mkdir(mode=0o700, parents=True)
        for name, source in bundle.items():
            path = args.output_dir / name
            path.write_text(source, encoding="utf-8")
            path.chmod(0o600 if name == "manifest.json" else 0o400)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"OPENBAO_AGENT_RENDER=FAIL ERROR={exc}") from exc
    print("OPENBAO_AGENT_RENDER=PASS")
    print("SECRET_VALUES_INCLUDED=NO")
    print("ENVIRONMENT_INJECTION_ENABLED=NO")


if __name__ == "__main__":
    main()

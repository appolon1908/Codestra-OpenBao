#!/usr/bin/env python3
"""Build a sanitized, non-destructive OpenBao control-plane plan."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENTS = {"development", "test", "staging", "production"}


def load(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if default is not None:
            return default
        raise


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def data(value):
    return value.get("data", value) if isinstance(value, dict) else value


def list_values(value) -> set[str]:
    value = data(value)
    if isinstance(value, list):
        return {str(item) for item in value}
    if isinstance(value, dict):
        for key in ("keys", "key_info"):
            if isinstance(value.get(key), list):
                return {str(item) for item in value[key]}
            if isinstance(value.get(key), dict):
                return {str(item) for item in value[key]}
    return set()


def selected(mapping: dict, keys: tuple[str, ...]) -> dict:
    return {key: mapping.get(key) for key in keys}


def build(environment: str, live_dir: Path, source_sha: str) -> dict:
    authority_path = ROOT / "config/workload-secret-authority.v1.json"
    roles_path = ROOT / "openbao/auth/jwt-roles.v1.json"
    audit_path = ROOT / "config/audit/audit.v1.json"
    engine_path = ROOT / "config/secrets/engines.v1.json"
    plugin_path = ROOT / "plugins/codestra-jwt-replay/plugin.v1.json"
    authority = load(authority_path)
    roles = load(roles_path)
    audit = load(audit_path)
    engines = load(engine_path)
    plugin = load(plugin_path)
    environment_config = load(ROOT / f"config/environments/{environment}/environment.json")
    mounts = data(load(live_dir / "mounts.json"))
    auths = data(load(live_dir / "auth.json"))
    audits = data(load(live_dir / "audit.json"))
    live_policies = list_values(load(live_dir / "policies.json"))
    live_plugin = data(load(live_dir / "plugin-info.json", {}))

    operations = []
    warnings = []

    plugin_payload = {
        "name": plugin["name"],
        "type": plugin["type"],
        "command": plugin["command"],
        "version": plugin["version"],
        "sha256": plugin["binarySha256"],
    }
    if not live_plugin:
        operations.append({
            "action": "create",
            "kind": "auth_plugin",
            "name": plugin["name"],
            "payload": plugin_payload,
        })
    elif selected(live_plugin, ("name", "command", "version", "sha256", "builtin")) != {
        "name": plugin["name"],
        "command": plugin["command"],
        "version": plugin["version"],
        "sha256": plugin["binarySha256"],
        "builtin": False,
    }:
        warnings.append("auth plugin version identity differs; overwriting an immutable plugin version is prohibited")

    desired_engine = next(item for item in engines["engines"] if item["path"] == "codestra/")
    live_mount = mounts.get("codestra/") if isinstance(mounts, dict) else None
    engine_compatible = live_mount is None
    engine_payload = {
        "path": "codestra",
        "type": "kv",
        "options": {"version": "2"},
        "description": desired_engine["purpose"],
    }
    if live_mount is None:
        operations.append({"action": "create", "kind": "secret_engine", "name": "codestra/", "payload": engine_payload})
    elif live_mount.get("type") != "kv" or (live_mount.get("options") or {}).get("version") != "2":
        engine_compatible = False
        warnings.append("codestra/ exists with an incompatible type or version; automatic replacement is prohibited")
    else:
        engine_compatible = True

    live_engine_config = data(load(live_dir / "codestra-config.json", {}))
    engine_config_payload = {
        "max_versions": desired_engine["maxVersions"],
        "cas_required": desired_engine["casRequired"],
        "delete_version_after": desired_engine["deleteVersionAfter"],
    }
    if engine_compatible and selected(live_engine_config, tuple(engine_config_payload)) != engine_config_payload:
        operations.append({
            "action": "update" if live_mount is not None else "create",
            "kind": "secret_engine_config",
            "name": "codestra/config",
            "payload": engine_config_payload,
        })

    auth_mount = roles["mount"] + "/"
    live_auth = auths.get(auth_mount) if isinstance(auths, dict) else None
    auth_compatible = live_auth is None
    if live_auth is None:
        operations.append({
            "action": "create",
            "kind": "auth_method",
            "name": auth_mount,
            "payload": {
                "path": roles["mount"],
                "type": "plugin",
                "plugin_name": plugin["name"],
                "plugin_version": plugin["version"],
                "plugin_sha256": plugin["binarySha256"],
            },
        })
    elif (
        live_auth.get("type") != plugin["name"]
        or live_auth.get("plugin_version") != plugin["version"]
        or live_auth.get("running_plugin_version") != plugin["version"]
        or live_auth.get("running_sha256") != plugin["binarySha256"]
    ):
        auth_compatible = False
        warnings.append(f"{auth_mount} does not run the exact replay-protected plugin; automatic replacement is prohibited")
    else:
        auth_compatible = True

    live_config = data(load(live_dir / "jwt-config.json", {}))
    desired_config = roles["mountConfiguration"]
    config_keys = ("oidc_discovery_url", "bound_issuer", "default_role", "jwt_supported_algs")
    if auth_compatible and selected(live_config, config_keys) != selected(desired_config, config_keys):
        operations.append({
            "action": "update" if live_config else "create",
            "kind": "auth_config",
            "name": f"auth/{roles['mount']}/config",
            "payload": desired_config,
        })

    desired_role_names = set()
    for role in roles["roles"]:
        if not role["name"].endswith("-" + environment):
            continue
        name = role["name"]
        desired_role_names.add(name)
        live_role = data(load(live_dir / "jwt-roles" / f"{name}.json", {}))
        role_keys = (
            "cel_program", "message", "clock_skew_leeway", "expiration_leeway",
            "not_before_leeway", "bound_audiences",
        )
        desired_payload = role["payload"]
        if auth_compatible and selected(live_role, role_keys) != selected(desired_payload, role_keys):
            operations.append({
                "action": "update" if live_role else "create",
                "kind": "jwt_role",
                "name": role["endpoint"],
                "payload": desired_payload,
            })
    observed_roles = list_values(load(live_dir / "jwt-roles.json", []))
    extra_roles = sorted(observed_roles - desired_role_names)
    if extra_roles:
        warnings.append("unmanaged JWT roles require manual review: " + ",".join(extra_roles))

    index = load(ROOT / "config/policies/generated-policy-index.v1.json")
    desired_policy_names = set()
    for item in index["policies"]:
        if item["environment"] != environment:
            continue
        name = item["policyName"]
        desired_policy_names.add(name)
        policy_path = ROOT / item["path"]
        live_path = live_dir / "policies" / f"{name}.hcl"
        live_source = live_path.read_text(encoding="utf-8") if live_path.is_file() else ""
        desired_source = policy_path.read_text(encoding="utf-8")
        if live_source.strip() != desired_source.strip():
            operations.append({
                "action": "update" if name in live_policies else "create",
                "kind": "policy",
                "name": name,
                "payload": {"policy": desired_source},
            })
    extra_policies = sorted(
        name for name in live_policies
        if name.startswith("workload-") and name.endswith("-" + environment) and name not in desired_policy_names
    )
    if extra_policies:
        warnings.append("unmanaged workload policies require manual review: " + ",".join(extra_policies))

    device = audit["device"]
    audit_mount = device["path"] + "/"
    live_audit = audits.get(audit_mount) if isinstance(audits, dict) else None
    audit_payload = {
        "path": device["path"],
        "type": device["type"],
        "options": {
            "file_path": device["filePath"],
            "mode": device["mode"],
            "format": device["format"],
            "hmac_accessor": str(device["hmacAccessor"]).lower(),
            "log_raw": str(device["logRaw"]).lower(),
        },
    }
    if live_audit is None:
        warnings.append(
            "declarative file-audit/ is absent; runtime restart/unseal or SIGHUP is required before apply"
        )
    else:
        live_options = live_audit.get("options") or {}
        if selected(live_options, tuple(audit_payload["options"])) != audit_payload["options"]:
            warnings.append("file-audit/ option drift requires protected manual remediation; replacement is prohibited")

    serialized = json.dumps(operations, sort_keys=True)
    for forbidden in ("root_token", "unseal_key", "client_secret", "private_key"):
        if forbidden in serialized.lower():
            raise ValueError(f"plan_contains_sensitive_field:{forbidden}")
    create_count = sum(item["action"] == "create" for item in operations)
    change_count = sum(item["action"] == "update" for item in operations)
    summary = [f"{item['action']}:{item['kind']}:{item['name']}" for item in operations]
    runtime_apply_authorized = all(
        value is True
        for value in (
            authority.get("runtimeApplyAuthorized"),
            roles.get("runtimeApplyAuthorized"),
            audit.get("runtimeApplyAuthorized"),
            engines.get("runtimeApplyAuthorized"),
            plugin.get("runtimeApplyAuthorized"),
            environment_config.get("runtimeApplyAuthorized"),
        )
    )
    return {
        "schemaVersion": 1,
        "planSourceSha": source_sha,
        "environment": environment,
        "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "planOnly": True,
        "runtimeApplyAuthorized": runtime_apply_authorized,
        "authorityChecksums": {
            str(authority_path.relative_to(ROOT)): sha(authority_path),
            str(roles_path.relative_to(ROOT)): sha(roles_path),
            str(audit_path.relative_to(ROOT)): sha(audit_path),
            str(engine_path.relative_to(ROOT)): sha(engine_path),
            str(plugin_path.relative_to(ROOT)): sha(plugin_path),
        },
        "counts": {"create": create_count, "change": change_count, "destroy": 0},
        "summary": summary,
        "warnings": warnings,
        "operations": operations,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", required=True, choices=sorted(ENVIRONMENTS))
    parser.add_argument("--live-dir", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if len(args.source_sha) != 40 or any(character not in "0123456789abcdef" for character in args.source_sha):
        raise SystemExit("OPENBAO_PLAN=FAIL ERROR=invalid_source_sha")
    try:
        plan = build(args.environment, args.live_dir, args.source_sha)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"OPENBAO_PLAN=FAIL ERROR={exc}") from exc
    args.output.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    print("OPENBAO_PLAN=PASS")
    print(f"PLAN_CREATE_COUNT={plan['counts']['create']}")
    print(f"PLAN_CHANGE_COUNT={plan['counts']['change']}")
    print("PLAN_DESTROY_COUNT=0")


if __name__ == "__main__":
    main()

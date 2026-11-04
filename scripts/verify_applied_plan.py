#!/usr/bin/env python3
"""Read back every applied plan operation without reading secret values."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

READ_TIMEOUT_SECONDS = 120


class ReadbackMismatch(ValueError):
    """A successful observation proves drift or resource absence."""


DURATION = re.compile(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?")


def command(*args: str) -> str:
    result = subprocess.run(["bao", *args], check=False, capture_output=True, text=True,
                            timeout=READ_TIMEOUT_SECONDS)
    if result.returncode != 0:
        # These exact diagnostics are emitted only by the vendored CLI's
        # successful logical/policy lookup with no resource. Exit 2 alone
        # also represents denied, unavailable and malformed responses.
        absent = (
            args[0] == "read" and result.stderr.strip() == "No value found at " + args[-1]
        ) or (
            args[:2] == ("policy", "read")
            and result.stderr.strip() == "No policy named: " + args[2]
        )
        if result.returncode == 2 and absent:
            raise ReadbackMismatch("readback_absent:" + args[0])
        raise ValueError("readback_command_failed:" + args[0])
    return result.stdout


def json_command(*args: str):
    return json.loads(command(*args))


def data(value):
    if not isinstance(value, dict):
        raise ValueError("readback_response_not_object")
    resource = value.get("data", value)
    if not isinstance(resource, dict):
        raise ValueError("readback_resource_not_object")
    return resource


def semantic(value):
    """OpenBao stores durations normalized ("2160h" reads back as "2160h0m0s")."""
    if isinstance(value, str) and value:
        match = DURATION.fullmatch(value)
        if match and any(match.groups()):
            hours, minutes, seconds = match.groups()
            return ("duration", int(hours or 0) * 3600 + int(minutes or 0) * 60 + float(seconds or 0))
    return value


def selected(mapping: dict, keys) -> dict:
    return {key: semantic(mapping.get(key)) for key in keys}


def verify(operation: dict) -> None:
    kind = operation["kind"]
    name = operation["name"]
    payload = operation["payload"]
    if kind == "auth_plugin":
        # A successful catalog observation establishes absence without
        # treating a denied or failed plugin-info request as a missing plugin.
        catalog = data(json_command("plugin", "list", "-format=json", "auth"))
        names, details = catalog.get("auth"), catalog.get("details")
        if (not isinstance(names, list) or any(not isinstance(name, str) or not name for name in names)
                or not isinstance(details, list)):
            raise ValueError("plugin_catalog_invalid")
        for entry in details:
            if (not isinstance(entry, dict) or entry.get("type") != "auth"
                    or not isinstance(entry.get("name"), str) or not entry["name"]
                    or not isinstance(entry.get("version", ""), str)):
                raise ValueError("plugin_catalog_invalid")
        if set(names) != {entry["name"] for entry in details}:
            raise ValueError("plugin_catalog_inconsistent")
        if not any(entry["name"] == payload["name"]
                   and entry.get("version", "") == payload["version"] for entry in details):
            raise ReadbackMismatch("auth_plugin_absent")
        item = data(json_command(
            "plugin", "info", "-format=json", f"-version={payload['version']}", "auth", payload["name"]
        ))
        if (any(not isinstance(item.get(key), str) for key in ("name", "command", "version", "sha256"))
                or not item["name"] or not isinstance(item.get("builtin"), bool)):
            raise ValueError("plugin_info_invalid")
        expected = selected(payload, ("name", "command", "version", "sha256"))
        if selected(item, tuple(expected)) != expected or item.get("builtin") is not False:
            raise ReadbackMismatch("auth_plugin_readback_mismatch")
    elif kind == "secret_engine":
        mounts = data(json_command("secrets", "list", "-format=json"))
        if name not in mounts:
            raise ReadbackMismatch("secret_engine_absent")
        item = mounts[name]
        if not isinstance(item, dict) or not isinstance(item.get("type"), str) or not item["type"]:
            raise ValueError("secret_engine_entry_invalid")
        options = item.get("options")
        if options is not None and (not isinstance(options, dict) or any(
                not isinstance(key, str) or not isinstance(value, str) for key, value in options.items())):
            raise ValueError("secret_engine_options_invalid")
        if item["type"] != "kv" or (options or {}).get("version") != "2":
            raise ReadbackMismatch("secret_engine_readback_mismatch")
    elif kind == "secret_engine_config":
        actual = data(json_command("read", "-format=json", name))
        keys = tuple(payload)
        if selected(actual, keys) != selected(payload, keys):
            raise ReadbackMismatch("secret_engine_config_readback_mismatch:" + name)
    elif kind == "auth_method":
        auths = data(json_command("auth", "list", "-format=json"))
        if name not in auths:
            raise ReadbackMismatch("auth_method_absent")
        item = auths[name]
        if not isinstance(item, dict) or not isinstance(item.get("type"), str) or not item["type"]:
            raise ValueError("auth_method_entry_invalid")
        if any(not isinstance(item.get(key), str)
               for key in ("plugin_version", "running_plugin_version", "running_sha256")):
            raise ValueError("auth_method_version_invalid")
        if (
            item["type"] != payload["plugin_name"]
            or item.get("plugin_version") != payload["plugin_version"]
            or item.get("running_plugin_version") != payload["plugin_version"]
            or item.get("running_sha256") != payload["plugin_sha256"]
        ):
            raise ReadbackMismatch("auth_method_readback_mismatch")
    elif kind == "policy":
        if command("policy", "read", name).strip() != payload["policy"].strip():
            raise ReadbackMismatch("policy_readback_mismatch:" + name)
    elif kind in {"auth_config", "jwt_role"}:
        actual = data(json_command("read", "-format=json", name))
        keys = tuple(payload)
        if selected(actual, keys) != selected(payload, keys):
            raise ReadbackMismatch(kind + "_readback_mismatch:" + name)
    else:
        raise ValueError("unknown_plan_kind:" + str(kind))


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_applied_plan.py PLAN.json")
    try:
        plan = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        for operation in plan["operations"]:
            verify(operation)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired) as exc:
        raise SystemExit(f"PLAN_APPLIED_EXACTLY=false ERROR={exc}") from exc
    print("PLAN_APPLIED_EXACTLY=true")
    print(f"PLAN_DESTROY_COUNT={plan['counts']['destroy']}")


if __name__ == "__main__":
    main()

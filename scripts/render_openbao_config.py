#!/usr/bin/env python3
"""Render a non-secret, environment-specific OpenBao server configuration."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "openbao/templates/openbao.hcl.tpl"
ENVIRONMENTS = {"development", "test", "staging", "production"}


def render(environment: str) -> str:
    if environment not in ENVIRONMENTS:
        raise ValueError("unsupported_environment")
    config_path = ROOT / f"config/environments/{environment}/environment.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if config.get("environment") != environment:
        raise ValueError("environment_identity_drift")
    networks = config.get("networks") or {}
    replacements = {
        "__ENVIRONMENT__": environment,
        "__API_ADDRESS__": config.get("canonicalApiAddress"),
        "__CLUSTER_ADDRESS__": config.get("clusterAddress"),
        "__RAFT_PATH__": config.get("raftPath"),
        "__NODE_ID__": config.get("nodeId"),
        "__TRUSTED_PROXY_CIDR__": networks.get("trustedProxyCidr"),
    }
    if any(not isinstance(value, str) or not value for value in replacements.values()):
        raise ValueError("render_value_missing")
    source = TEMPLATE.read_text(encoding="utf-8")
    for marker, value in replacements.items():
        if marker not in source:
            raise ValueError(f"template_marker_missing:{marker}")
        if any(character in value for character in ('"', "\n", "\r")):
            raise ValueError(f"unsafe_render_value:{marker}")
        source = source.replace(marker, value)
    unresolved = sorted(set(re.findall(r"__[A-Z0-9_]+__", source)))
    if unresolved:
        raise ValueError("unresolved_markers:" + ",".join(unresolved))
    return source


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("environment", choices=sorted(ENVIRONMENTS))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    source = render(args.environment)
    if args.output:
        args.output.write_text(source, encoding="utf-8")
    else:
        print(source, end="")


if __name__ == "__main__":
    main()

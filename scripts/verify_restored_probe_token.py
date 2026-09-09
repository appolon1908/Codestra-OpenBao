#!/usr/bin/env python3
"""Fail-closed validation for the one-use post-restore probe token.

The token itself never enters this process. The caller supplies only the JSON
returned by ``bao token lookup -format=json`` on standard input and the exact
expected direct policy name. No token metadata is printed on failure.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from typing import Any, NoReturn, Sequence

FORBIDDEN_POLICY_NAMES = frozenset({"default", "root"})


class ProbeTokenValidationError(ValueError):
    """Raised when the restored probe token is not strictly bounded."""


def _fail(message: str) -> NoReturn:
    raise ProbeTokenValidationError(message)


def _string_list(value: Any, *, field: str, missing: bool = False) -> list[str]:
    if value is None and missing:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        _fail(f"{field} must be an array of strings")
    return value


def validate_probe_token(document: Any, expected_policy: str) -> None:
    if not expected_policy or len(expected_policy) > 128:
        _fail("expected policy is invalid")
    if expected_policy.casefold() in FORBIDDEN_POLICY_NAMES:
        _fail("reserved default/root policies are prohibited for restore probes")
    if not isinstance(document, Mapping):
        _fail("lookup response must be an object")
    data = document.get("data")
    if not isinstance(data, Mapping):
        _fail("lookup response data must be an object")

    direct_policies = _string_list(data.get("policies"), field="policies")
    if direct_policies != [expected_policy]:
        _fail("direct policy set is not the one expected policy")

    # Some OpenBao response shapes expose token_policies in addition to
    # policies. When present, it must agree exactly rather than creating a
    # second effective-policy interpretation.
    if "token_policies" in data:
        token_policies = _string_list(
            data.get("token_policies"), field="token_policies"
        )
        if token_policies != [expected_policy]:
            _fail("token policy set is not the one expected policy")

    identity_policies = _string_list(
        data.get("identity_policies"), field="identity_policies", missing=True
    )
    if identity_policies:
        _fail("inherited identity policies are prohibited")

    external_policies = data.get("external_namespace_policies", {})
    if external_policies is None:
        external_policies = {}
    if not isinstance(external_policies, Mapping):
        _fail("external_namespace_policies must be an object")
    if external_policies:
        _fail("inherited external-namespace policies are prohibited")

    if data.get("renewable") is not False:
        _fail("probe token must be explicitly non-renewable")
    ttl = data.get("ttl")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
        _fail("probe token must have a positive integer TTL")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-policy", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        document = json.load(sys.stdin)
        validate_probe_token(document, args.expected_policy)
    except (json.JSONDecodeError, ProbeTokenValidationError) as exc:
        print(f"RESTORED_PROBE_TOKEN_POLICY=FAIL: {exc}", file=sys.stderr)
        return 1
    print("RESTORED_PROBE_TOKEN_POLICY=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

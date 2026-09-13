#!/usr/bin/env python3
"""Verify one restored test value by hash without printing secret material."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True)
    parser.add_argument("--field", required=True)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    if not args.path.startswith("codestra/") or ".." in args.path or "*" in args.path:
        raise SystemExit("RESTORE_SECRET_PROBE=FAIL ERROR=unsafe_path")
    if len(args.expected_sha256) != 64:
        raise SystemExit("RESTORE_SECRET_PROBE=FAIL ERROR=invalid_hash")
    result = subprocess.run(
        ["bao", "kv", "get", "-format=json", args.path],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit("RESTORE_SECRET_PROBE=FAIL ERROR=read_failed")
    try:
        value = json.loads(result.stdout)["data"]["data"][args.field]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SystemExit("RESTORE_SECRET_PROBE=FAIL ERROR=field_missing") from exc
    actual = hashlib.sha256(str(value).encode()).hexdigest()
    value = None
    if actual != args.expected_sha256:
        raise SystemExit("RESTORE_SECRET_PROBE=FAIL ERROR=hash_mismatch")
    print("RESTORE_SECRET_PROBE=PASS")


if __name__ == "__main__":
    main()

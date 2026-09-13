#!/usr/bin/env python3
"""Compare two hash-only SSH baselines without exposing SSH configuration."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def normalized(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    value.pop("capturedAt", None)
    return value


if len(sys.argv) != 3:
    raise SystemExit("usage: verify_ssh_unchanged.py BEFORE.json AFTER.json")
try:
    unchanged = normalized(Path(sys.argv[1])) == normalized(Path(sys.argv[2]))
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"SSH_CHANGED=UNKNOWN ERROR={exc}") from exc
if not unchanged:
    raise SystemExit("SSH_CHANGED=YES")
print("SSH_CHANGED=NO")

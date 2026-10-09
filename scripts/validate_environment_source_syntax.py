#!/usr/bin/env python3
"""Fail-closed strict JSON/Python validation with *only* declared TypeScript JSONC.

The two vendored tsconfig.json source files use TypeScript's documented JSONC
syntax. All other files remain strict RFC JSON; malformed or unterminated
comments fail. Never strip comments in general credential/config JSON.
"""
from __future__ import annotations

import json
import py_compile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JSONC_FILES = frozenset({
    "upstream/ui/tsconfig.json",
    "upstream/website/tsconfig.json",
})
SKIP_PARTS = frozenset({".git", "node_modules", ".venv", "vendor"})


def parse_jsonc(raw: str):
    out = []
    i = 0
    in_string = False
    escaped = False
    while i < len(raw):
        ch = raw[i]
        nxt = raw[i + 1] if i + 1 < len(raw) else ""
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
        elif ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif ch == "/" and nxt == "/":
            i += 2
            while i < len(raw) and raw[i] not in "\r\n":
                i += 1
        elif ch == "/" and nxt == "*":
            end = raw.find("*/", i + 2)
            if end == -1:
                raise ValueError("unterminated_jsonc_comment")
            out.extend("\n" for x in raw[i:end + 2] if x == "\n")
            i = end + 2
        else:
            out.append(ch)
            i += 1
    if in_string:
        raise ValueError("unterminated_jsonc_string")
    sanitized = "".join(out)
    # Trailing commas may appear only outside strings; scan a second time.
    out = []
    in_string = escaped = False
    for index, ch in enumerate(sanitized):
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
            out.append(ch)
        elif ch == "," and sanitized[index + 1:].lstrip().startswith(("}", "]")):
            continue
        else:
            out.append(ch)
    return json.loads("".join(out))


def validate_tree(root: Path = ROOT) -> tuple[int, int]:
    json_count = py_count = 0
    for path in sorted(root.rglob("*.json")):
        if SKIP_PARTS.intersection(path.relative_to(root).parts):
            continue
        source = path.read_text(encoding="utf-8")
        rel = path.relative_to(root).as_posix()
        if rel in JSONC_FILES:
            parse_jsonc(source)
        else:
            json.loads(source)
        json_count += 1
    for path in sorted(root.rglob("*.py")):
        if SKIP_PARTS.intersection(path.relative_to(root).parts):
            continue
        py_compile.compile(str(path), doraise=True)
        py_count += 1
    return json_count, py_count


if __name__ == "__main__":
    n, m = validate_tree()
    print(f"OPENBAO_ENVIRONMENT_SYNTAX=PASS json={n} python={m}")

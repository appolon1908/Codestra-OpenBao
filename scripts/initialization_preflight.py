#!/usr/bin/env python3
"""Validate custody paths without creating, chmodding, or contacting anything."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def absolute_path(value: str) -> Path:
    if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("invalid_path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute_path_required")
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError("symbolic_path_prohibited")
    return path


def validate(environ: dict[str, str], repo_root: Path = ROOT) -> None:
    custody = absolute_path(environ.get("OPENBAO_INIT_CUSTODY_DIR", ""))
    parent = custody.parent.resolve(strict=True)
    for forbidden in (repo_root.resolve(), Path("/tmp"), Path("/var/tmp"), Path("/dev/shm")):
        if parent == forbidden or forbidden in parent.parents:
            raise ValueError("custody_must_be_persistent_and_outside_repository")
    info = parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise ValueError("custody_parent_owner_mismatch")
    if stat.S_IMODE(info.st_mode) != 0o700 or not os.access(parent, os.W_OK | os.X_OK):
        raise ValueError("custody_parent_requires_private_writable_directory")
    if os.path.lexists(custody):
        raise ValueError("custody_destination_already_exists")

    keys = environ.get("OPENBAO_UNSEAL_PGP_KEY_FILES", "").split(":")
    if len(keys) != 5 or any(not key for key in keys):
        raise ValueError("five_public_key_paths_required")
    keys.append(environ.get("OPENBAO_ROOT_TOKEN_PGP_KEY_FILE", ""))
    resolved_keys = []
    for value in keys:
        if "," in value or ":" in value:
            raise ValueError("ambiguous_public_key_path")
        path = absolute_path(value)
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
            raise ValueError("nonempty_public_key_file_required")
        if not os.access(path, os.R_OK):
            raise ValueError("public_key_file_unreadable")
        resolved_keys.append((info.st_dev, info.st_ino))
    if len(set(resolved_keys)) != 6:
        raise ValueError("six_distinct_public_key_files_required")


def main() -> int:
    try:
        validate(dict(os.environ))
    except (OSError, ValueError):
        # Do not echo user-controlled paths or filesystem exception messages.
        print("OPENBAO_INITIALIZATION_INPUTS=FAIL check protected custody and public-key paths", file=sys.stderr)
        return 2
    print("OPENBAO_INITIALIZATION_INPUTS=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

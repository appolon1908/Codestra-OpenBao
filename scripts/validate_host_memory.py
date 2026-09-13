#!/usr/bin/env python3
"""Fail closed unless active swap is absent or backed by a crypt device."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def active_swaps(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or not lines[0].startswith("Filename"):
        raise ValueError("invalid_proc_swaps")
    devices = []
    for line in lines[1:]:
        fields = line.split()
        if fields:
            devices.append(fields[0])
    return devices


def device_type(device: str, fixture: dict[str, str] | None) -> str:
    if fixture is not None:
        value = fixture.get(device)
        if not value:
            raise ValueError(f"swap_device_type_unknown:{device}")
        return value
    result = subprocess.run(
        ["lsblk", "--noheadings", "--output", "TYPE", device],
        check=False,
        capture_output=True,
        text=True,
    )
    values = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if result.returncode != 0 or not values:
        raise ValueError(f"swap_device_type_unknown:{device}")
    return values[-1]


def validate(swaps_path: Path, fixture: dict[str, str] | None = None) -> tuple[str, int]:
    devices = active_swaps(swaps_path)
    if not devices:
        return "disabled", 0
    unencrypted = [device for device in devices if device_type(device, fixture) != "crypt"]
    if unencrypted:
        raise ValueError("unencrypted_swap_active:" + ",".join(unencrypted))
    return "encrypted", len(devices)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proc-swaps", type=Path, default=Path("/proc/swaps"))
    parser.add_argument("--device-types-json", type=Path)
    args = parser.parse_args()
    fixture = None
    if args.device_types_json:
        fixture = json.loads(args.device_types_json.read_text(encoding="utf-8"))
    try:
        mode, count = validate(args.proc_swaps, fixture)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"OPENBAO_HOST_MEMORY=FAIL ERROR={exc}") from exc
    print("OPENBAO_HOST_MEMORY=PASS")
    print(f"SWAP_MODE={mode}")
    print(f"ACTIVE_SWAP_DEVICES={count}")


if __name__ == "__main__":
    main()

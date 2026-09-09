#!/usr/bin/env python3
"""Project bao status or /v1/sys/health JSON to a non-secret readiness result."""
import json
import sys


def readiness(status):
    if not isinstance(status, dict) or any(type(status.get(key)) is not bool
                                          for key in ("initialized", "sealed")):
        return {"ready": False, "state": "unknown", "reason": "invalid_status"}
    initialized, sealed = status["initialized"], status["sealed"]
    if not initialized and not sealed:
        return {"ready": False, "state": "unknown", "reason": "inconsistent_status"}
    return {"ready": initialized and not sealed, "initialized": initialized,
            "sealed": sealed, "state": "uninitialized" if not initialized else
            ("sealed" if sealed else "unsealed"),
            "bootstrap_required": not initialized,
            "policy_and_restore_verified": False}


def main():
    try:
        report = readiness(json.load(sys.stdin))
    except (ValueError, OSError):
        report = {"ready": False, "state": "unknown", "reason": "invalid_status"}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

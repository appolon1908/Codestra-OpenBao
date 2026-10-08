#!/usr/bin/env python3
"""Enforce the reviewed promotion path: development -> test -> staging -> production -> main.

Reviewed implementation heads may target development; protected environment branches
may only move forward through the promotion chain. With --require-current, a local
head must also contain the given development ref, so stale work is rejected before
a pull request is opened. The ob-15-cicd section also accepts strictly named
subsection heads for review, without changing environment promotions.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTECTED = ("development", "test", "staging", "production", "main")
DEVELOPMENT_HEAD_PREFIXES = (
    "remediation/",
    "sync/openbao-upstream-",
    "feat/",
    "feature/",
    "fix/",
    "chore/",
    "docs/",
    "refactor/",
    "ci/",
)
PROMOTIONS = {
    "test": "development",
    "staging": "test",
    "production": "staging",
    "main": "production",
}


def fail(message: str) -> None:
    raise SystemExit(f"OPENBAO_BRANCH_PROMOTION=FAIL {message}")


def admissible_development_head(head: str) -> bool:
    return any(
        head.startswith(prefix) and len(head) > len(prefix) and head not in PROTECTED
        for prefix in DEVELOPMENT_HEAD_PREFIXES
    )


def promotion_allowed(base: str, head: str) -> bool:
    if base == "development":
        return admissible_development_head(head)
    # A section review can accept only its own strictly named subsection;
    # it does not grant promotion into testing, staging, or production.
    if base == "ob-15-cicd":
        return re.fullmatch(r"subsection/ob-15-cicd--[a-z0-9]+(?:-[a-z0-9]+)*", head) is not None
    return base in PROMOTIONS and head == PROMOTIONS[base]


def check_event(event: str, base: str, head: str, ref_name: str) -> None:
    # Any event other than the three the workflow subscribes to (including an unset
    # EVENT_NAME) fails closed rather than silently passing the promotion check.
    if event == "pull_request":
        if not promotion_allowed(base, head):
            fail(f"{head} -> {base}")
    elif event == "push":
        if ref_name not in PROTECTED:
            fail("unexpected push branch")
    elif event == "workflow_dispatch":
        if ref_name not in PROTECTED and not admissible_development_head(ref_name):
            fail("unexpected dispatch branch")
    else:
        fail(f"unsupported event {event!r}")


def require_current(head_ref: str, development_ref: str) -> None:
    status = subprocess.run(
        ["git", "merge-base", "--is-ancestor", development_ref, head_ref],
        cwd=ROOT,
        check=False,
    ).returncode
    if status != 0:
        fail(f"{head_ref} does not contain {development_ref}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", default=os.environ.get("EVENT_NAME", ""))
    parser.add_argument("--base", default=os.environ.get("BASE_REF", ""))
    parser.add_argument("--head", default=os.environ.get("HEAD_REF", ""))
    parser.add_argument("--ref-name", default=os.environ.get("REF_NAME", ""))
    parser.add_argument("--require-current", metavar="DEVELOPMENT_REF")
    args = parser.parse_args(argv)
    check_event(args.event, args.base, args.head, args.ref_name)
    if args.require_current:
        require_current("HEAD", args.require_current)
    print("OPENBAO_BRANCH_PROMOTION=PASS")


if __name__ == "__main__":
    main(sys.argv[1:])

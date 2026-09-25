#!/usr/bin/env python3
"""Submit Shamir unseal shares from protected files without logging values."""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.parse
import urllib.request
from pathlib import Path


LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def context() -> ssl.SSLContext | None:
    address = os.environ.get("BAO_ADDR", "")
    parsed = urllib.parse.urlsplit(address)
    if parsed.scheme == "http":
        # Unseal shares may cross the wire in cleartext only to a local listener
        # outside production (the ephemeral isolated-restore/integration target).
        if parsed.hostname not in LOOPBACK_HOSTS:
            raise ValueError("cleartext unseal is only permitted to a loopback address")
        if os.environ.get("CODESTRA_ENVIRONMENT") == "production":
            raise ValueError("cleartext unseal is prohibited in production")
        return None
    if parsed.scheme != "https":
        raise ValueError("BAO_ADDR must use https")
    ca = os.environ.get("BAO_CACERT")
    if not ca:
        raise ValueError("BAO_CACERT is required for HTTPS")
    value = ssl.create_default_context(cafile=ca)
    cert = os.environ.get("BAO_CLIENT_CERT")
    key = os.environ.get("BAO_CLIENT_KEY")
    if bool(cert) != bool(key):
        raise ValueError("both BAO_CLIENT_CERT and BAO_CLIENT_KEY are required for mTLS")
    if cert and key:
        value.load_cert_chain(cert, key)
    return value


def submit(address: str, share: str, tls: ssl.SSLContext | None) -> dict:
    request = urllib.request.Request(
        address.rstrip("/") + "/v1/sys/unseal",
        data=json.dumps({"key": share}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, context=tls, timeout=15) as response:
        value = json.loads(response.read())
    if not isinstance(value, dict) or type(value.get("sealed")) is not bool:
        raise ValueError("invalid unseal response")
    return value


def main() -> None:
    address = os.environ.get("BAO_ADDR")
    files = os.environ.get("OPENBAO_UNSEAL_KEY_FILES", "").split(":")
    if not address or not files or any(not item for item in files):
        raise SystemExit("OPENBAO_UNSEAL=FAIL ERROR=address_or_key_files_missing")
    try:
        tls = context()
        for index, item in enumerate(files, start=1):
            path = Path(item)
            if not path.is_file() or path.is_symlink():
                raise ValueError("unseal key file is missing or symbolic")
            share = path.read_text(encoding="utf-8").strip()
            if not share:
                raise ValueError("unseal key file is empty")
            result = submit(address, share, tls)
            share = ""
            if result["sealed"] is False:
                print("OPENBAO_UNSEAL=PASS")
                print(f"UNSEAL_SHARES_SUBMITTED={index}")
                return
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"OPENBAO_UNSEAL=FAIL ERROR={exc}") from exc
    raise SystemExit("OPENBAO_UNSEAL=FAIL ERROR=threshold_not_reached")


if __name__ == "__main__":
    main()

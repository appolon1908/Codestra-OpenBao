#!/usr/bin/env python3
"""Submit Shamir unseal shares from protected files without logging values."""

from __future__ import annotations

import json
import ipaddress
from http.client import HTTPException
import os
import ssl
import stat
import sys
import urllib.parse
import urllib.request
from pathlib import Path


def validate_address(address: str, environment: str) -> None:
    if environment not in {"development", "test", "staging", "production"}:
        raise ValueError("explicit environment required")
    if not address or any(char.isspace() or ord(char) < 32 for char in address):
        raise ValueError("invalid server address")
    parsed = urllib.parse.urlsplit(address)
    # Access port to reject malformed or out-of-range values before reading shares.
    parsed.port
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise ValueError("server address must be a plain HTTP(S) origin")
    if parsed.scheme == "http":
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = parsed.hostname == "localhost"
        if environment not in {"development", "test"} or not loopback:
            raise ValueError("HTTP is restricted to isolated development/test loopback")


def context() -> ssl.SSLContext | None:
    address = os.environ.get("BAO_ADDR", "")
    validate_address(address, os.environ.get("CODESTRA_ENVIRONMENT", ""))
    if urllib.parse.urlsplit(address).scheme == "http":
        return None
    ca = os.environ.get("BAO_CACERT")
    if not ca:
        raise ValueError("BAO_CACERT is required for HTTPS")
    value = ssl.create_default_context(cafile=ca)
    value.minimum_version = ssl.TLSVersion.TLSv1_3
    cert = os.environ.get("BAO_CLIENT_CERT")
    key = os.environ.get("BAO_CLIENT_KEY")
    if not cert or not key:
        raise ValueError("both BAO_CLIENT_CERT and BAO_CLIENT_KEY are required for mTLS")
    value.load_cert_chain(cert, key)
    return value


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("unseal endpoint redirects are prohibited")


def submit(address: str, share: str, tls: ssl.SSLContext | None) -> dict:
    request = urllib.request.Request(
        address.rstrip("/") + "/v1/sys/unseal",
        data=json.dumps({"key": share}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    # Do not forward recovery material via environment-configured proxies or
    # follow redirects to a different endpoint.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=tls),
        NoRedirects(),
    )
    with opener.open(request, timeout=15) as response:
        value = json.loads(response.read())
    if not isinstance(value, dict) or type(value.get("sealed")) is not bool:
        raise ValueError("invalid unseal response")
    return value


def read_shares(files: list[str]) -> list[str]:
    if not 1 <= len(files) <= 5:
        raise ValueError("one to five share files required")
    values: list[str] = []
    identities: set[tuple[int, int]] = set()
    for item in files:
        path = Path(item)
        if not path.is_absolute() or ".." in path.parts or any(
            component.is_symlink() for component in (path, *path.parents)
        ):
            raise ValueError("share file must use an absolute nonsymbolic path")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "r", encoding="utf-8") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) not in {0o400, 0o600}
                    or not 0 < info.st_size <= 16384):
                raise ValueError("share file must be private, owned, regular and bounded")
            identity = (info.st_dev, info.st_ino)
            if identity in identities:
                raise ValueError("duplicate share file")
            identities.add(identity)
            share = source.read(16385).strip()
        if not share or len(share) > 16384 or share in values:
            raise ValueError("empty, oversized or duplicate share")
        values.append(share)
    return values


def main(*, validate_only: bool = False) -> None:
    address = os.environ.get("BAO_ADDR")
    files = os.environ.get("OPENBAO_UNSEAL_KEY_FILES", "").split(":")
    if not address or not files or any(not item for item in files):
        raise SystemExit("OPENBAO_UNSEAL=FAIL ERROR=address_or_key_files_missing")
    shares: list[str] = []
    try:
        tls = context()
        # Validate the entire batch before submitting the first share.
        shares = read_shares(files)
        if validate_only:
            print("OPENBAO_UNSEAL_INPUTS=PASS")
            return
        for index, share in enumerate(shares, start=1):
            result = submit(address, share, tls)
            shares[index - 1] = ""
            share = ""
            if result["sealed"] is False:
                print("OPENBAO_UNSEAL=PASS")
                print(f"UNSEAL_SHARES_SUBMITTED={index}")
                return
    except (OSError, ValueError, HTTPException):
        # Exceptions may contain URLs, local paths, or remote response content.
        raise SystemExit("OPENBAO_UNSEAL=FAIL ERROR=validation_or_transport_failed") from None
    finally:
        shares.clear()
    raise SystemExit("OPENBAO_UNSEAL=FAIL ERROR=threshold_not_reached")


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--check-inputs"]):
        raise SystemExit("OPENBAO_UNSEAL=FAIL ERROR=unsupported_arguments")
    main(validate_only=sys.argv[1:] == ["--check-inputs"])

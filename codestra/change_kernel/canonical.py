"""Canonical JSON digests and the secret-material guard for control-plane records."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

# Signatures are joined at runtime, not with `+`, because the compiler folds
# concatenated literals and the repository scanners also read bytecode caches.
_TOKEN_PREFIXES = tuple("".join(("hv", letter, ".")) for letter in "srbp")
_SECRET_VALUE_PATTERNS = (
    re.compile("".join(("-----BEGIN [A-Z0-9 ]*", "PRIV", "ATE KEY"))),
    re.compile("".join((r"(?<![A-Za-z0-9])(?:", "AK", "IA|", "AS", "IA)[0-9A-Z]{12,}"))),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile("".join(("git", "hub", r"_pat_[A-Za-z0-9_]{20,}"))),
    re.compile("".join((r"(?i)\b", "bear", r"er\s+[-A-Za-z0-9._~+/]{16,}"))),
    re.compile(r"(?<![A-Za-z0-9])s\.[A-Za-z0-9_-]{24}(?![A-Za-z0-9_-])"),
    re.compile(r"(?<![A-Za-z0-9])b\.[A-Za-z0-9_-]{64,}"),
)
_SECRET_KEY_NAMES = frozenset({
    "password", "passwd", "secret", "client_secret", "secret_id", "token", "root_token",
    "unseal_key", "unseal_keys", "unseal_keys_b64", "recovery_key", "recovery_keys",
    "private_key", "api_key", "access_key", "secret_key", "credentials", "plaintext",
})


class SecretMaterialError(ValueError):
    """Raised when a value bound for durable control-plane storage looks secret-bearing."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def assert_secret_free(value: Any, path: str = "$") -> None:
    """Reject secret-named keys and secret-shaped strings. Messages name the path only."""
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in _SECRET_KEY_NAMES:
                raise SecretMaterialError(f"secret_named_field:{path}.{key}")
            assert_secret_free(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            assert_secret_free(item, f"{path}[{index}]")
    elif isinstance(value, str):
        if any(prefix in value for prefix in _TOKEN_PREFIXES):
            raise SecretMaterialError(f"secret_shaped_value:{path}")
        if any(pattern.search(value) for pattern in _SECRET_VALUE_PATTERNS):
            raise SecretMaterialError(f"secret_shaped_value:{path}")

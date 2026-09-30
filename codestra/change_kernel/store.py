"""Durable storage over SQLite or PostgreSQL with one dialect-neutral schema."""

from __future__ import annotations

import sqlite3
import urllib.parse
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .canonical import sha256_bytes

MIGRATIONS = Path(__file__).resolve().parents[2] / "config/change-kernel/migrations"


class StoreError(RuntimeError):
    """Persistence is unavailable or inconsistent; callers must not mutate OpenBao."""


class Store:
    def __init__(self, url: str) -> None:
        self.url = url
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme == "sqlite":
            self.dialect = "sqlite"
            target = url[len("sqlite:///"):] if url.startswith("sqlite:///") else ""
            if url == "sqlite::memory:":
                target = ":memory:"
            if not target:
                raise StoreError("sqlite_url_must_be_sqlite:///PATH_or_sqlite::memory:")
            self._conn = sqlite3.connect(target, isolation_level=None, timeout=30)
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA busy_timeout = 30000")
        elif parsed.scheme in {"postgresql", "postgres"}:
            try:
                import psycopg  # type: ignore[import-not-found]
            except ImportError as exc:
                raise StoreError("psycopg_required_for_postgresql") from exc
            self.dialect = "postgresql"
            self._conn = psycopg.connect(url, autocommit=True)
        else:
            raise StoreError("unsupported_database_url_scheme")
        self._depth = 0

    def close(self) -> None:
        self._conn.close()

    def _sql(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.dialect == "postgresql" else sql

    @property
    def for_update(self) -> str:
        return " FOR UPDATE" if self.dialect == "postgresql" else ""

    @contextmanager
    def transaction(self) -> Iterator["Store"]:
        """Serializable-enough write transaction: IMMEDIATE on SQLite, row locks on PostgreSQL."""
        if self._depth:
            raise StoreError("nested_transaction")
        self._depth = 1
        begin = "BEGIN IMMEDIATE" if self.dialect == "sqlite" else "BEGIN ISOLATION LEVEL SERIALIZABLE"
        self._conn.execute(begin)
        try:
            yield self
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        else:
            self._conn.execute("COMMIT")
        finally:
            self._depth = 0

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        cursor = self._conn.execute(self._sql(sql), params)
        return cursor.rowcount

    def one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        rows = self.all(sql, params)
        return rows[0] if rows else None

    def all(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        cursor = self._conn.execute(self._sql(sql), params)
        names = [column[0] for column in cursor.description or ()]
        return [dict(zip(names, row)) for row in cursor.fetchall()]

    def migrate(self, directory: Path = MIGRATIONS) -> list[str]:
        applied = []
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations "
            "(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL, checksum TEXT NOT NULL)"
        )
        for path in sorted(directory.glob("*.sql")):
            version = path.stem
            # Checkouts may convert line endings; the recorded checksum must not depend on them.
            body = path.read_bytes().replace(b"\r\n", b"\n")
            checksum = sha256_bytes(body)
            existing = self.one("SELECT checksum FROM schema_migrations WHERE version = ?", (version,))
            if existing:
                if existing["checksum"] != checksum:
                    raise StoreError(f"applied_migration_changed:{version}")
                continue
            statements = [part.strip() for part in body.decode("utf-8").split(";") if part.strip()]
            with self.transaction():
                for statement in statements:
                    lines = [line for line in statement.splitlines() if not line.strip().startswith("--")]
                    if "\n".join(lines).strip():
                        self.execute("\n".join(lines))
                self.execute(
                    "INSERT INTO schema_migrations (version, applied_at, checksum) "
                    "VALUES (?, CURRENT_TIMESTAMP, ?)",
                    (version, checksum),
                )
            applied.append(version)
        return applied

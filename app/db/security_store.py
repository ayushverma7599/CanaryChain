"""SQLite persistence for the audit log (the only table the chain uses).

Follows the same connection pattern as app/db/database.py (one connection,
RLock, BEGIN IMMEDIATE, parameterized SQL) and keeps hash logic out: the chain
module builds entries, this module only stores them. No code path updates or
deletes rows.
"""

import json
import os
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

from app.db.models_security import AuditEntry
from app.security.constants import GENESIS_HASH


class SecurityDatabaseError(RuntimeError):
    """Raised when a security persistence operation cannot be completed."""


_COLUMNS = (
    "event_id, timestamp, tenant, event_type, canary_type, atlas_technique, "
    "severity_score, details, prev_hash, entry_hash"
)


class SecurityStore:
    """Append-only audit log storage."""

    def __init__(self, path: str | Path | None = None, timeout: float = 5.0) -> None:
        configured = path or os.environ.get("SECURITY_DATABASE_PATH")
        if configured is None:
            configured = Path.home() / ".canarychain" / "security.sqlite3"
        self.path = str(configured) if str(configured) == ":memory:" else str(Path(configured).expanduser())
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        try:
            if self.path != ":memory:":
                Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(self.path, timeout=timeout, check_same_thread=False)
            self._connection.row_factory = sqlite3.Row
            self._initialize()
        except (OSError, sqlite3.Error) as exc:
            if self._connection is not None:
                self._connection.close()
            raise SecurityDatabaseError("could not initialize security database") from exc

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                yield self._connection
                self._connection.commit()
            except sqlite3.Error as exc:
                self._connection.rollback()
                raise SecurityDatabaseError("security database transaction failed") from exc
            except BaseException:
                self._connection.rollback()
                raise

    def _initialize(self) -> None:
        with self._transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    tenant TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    canary_type TEXT,
                    atlas_technique TEXT NOT NULL,
                    severity_score REAL,
                    details TEXT NOT NULL,
                    prev_hash TEXT NOT NULL UNIQUE,
                    entry_hash TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def _entry(row: sqlite3.Row) -> AuditEntry:
        try:
            details = json.loads(row["details"])
        except ValueError:
            details = {"__unparseable__": row["details"]}  # forces a hash mismatch on verify
        return AuditEntry(
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            tenant=row["tenant"],
            event_type=row["event_type"],
            canary_type=row["canary_type"],
            atlas_technique=row["atlas_technique"],
            severity_score=row["severity_score"],
            details=details,
            prev_hash=row["prev_hash"],
            entry_hash=row["entry_hash"],
        )

    def append_audit(self, build_entry: Callable[[str], AuditEntry]) -> AuditEntry:
        """Atomically read the head hash, build the next entry from it, and insert it.

        The UNIQUE constraint on prev_hash additionally makes a fork impossible.
        """
        with self._transaction() as connection:
            row = connection.execute("SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
            entry = build_entry(row["entry_hash"] if row else GENESIS_HASH)
            connection.execute(
                f"INSERT INTO audit_log ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.event_id,
                    entry.timestamp,
                    entry.tenant,
                    entry.event_type,
                    entry.canary_type,
                    entry.atlas_technique,
                    entry.severity_score,
                    json.dumps(entry.details, sort_keys=True, separators=(",", ":")),
                    entry.prev_hash,
                    entry.entry_hash,
                ),
            )
            return entry

    def _select(self, where: str, params: tuple, order: str, limit: int | None) -> list[AuditEntry]:
        sql = f"SELECT {_COLUMNS} FROM audit_log {where} ORDER BY seq {order}"
        if limit is not None:
            sql += " LIMIT ?"
            params = (*params, limit)
        with self._lock:
            try:
                return [self._entry(row) for row in self._connection.execute(sql, params).fetchall()]
            except sqlite3.Error as exc:
                raise SecurityDatabaseError("could not read audit log") from exc

    def iter_audit(self) -> list[AuditEntry]:
        """All entries, oldest first (used by the verifier)."""
        return self._select("", (), "ASC", None)

    def list_audit(self, limit: int = 200) -> list[AuditEntry]:
        """Newest entries first."""
        return self._select("", (), "DESC", limit)

    def list_canary(self, limit: int = 200) -> list[AuditEntry]:
        """Newest canary-trip entries first."""
        return self._select("WHERE canary_type IS NOT NULL", (), "DESC", limit)

    def canary_since(self, iso_timestamp: str) -> list[AuditEntry]:
        """Canary entries at or after a UTC ISO timestamp (used for repeat detection)."""
        return self._select("WHERE canary_type IS NOT NULL AND timestamp >= ?", (iso_timestamp,), "ASC", None)

    def close(self) -> None:
        """Close the connection."""
        with self._lock:
            self._connection.close()


@lru_cache(maxsize=1)
def get_security_store() -> SecurityStore:
    """Process-wide store used by the API dependencies."""
    return SecurityStore()

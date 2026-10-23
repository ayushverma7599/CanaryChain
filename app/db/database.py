"""SQLite persistence for core requests, results, and prompt policy rules.

This database is separate from Member B's security-event and audit-chain
storage. Set CORE_DATABASE_PATH to choose a persistent file location.
"""

import os
import re
import sqlite3
import threading
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Iterator

from app.db.models_core import CoreRecord, DefensiveRule

DEFAULT_DEFENSIVE_RULE = DefensiveRule(
    rule_id="credential-disclosure-request",
    pattern=(
        r"\b(?:reveal|show|print|expose|steal|leak|exfiltrate)\b"
        r"[\s\S]{0,80}\b(?:api\s*keys?|credentials?|secrets?|tokens?)\b"
    ),
    description="Requests to disclose or exfiltrate credentials are denied.",
)

_OPERATIONS = {"attack", "query", "defense"}
_STATUSES = {"completed", "denied", "gateway_error"}


class CoreDatabaseError(RuntimeError):
    """Raised when a core persistence operation cannot be completed."""


class CoreDatabase:
    """Small SQLite repository using serialized, parameterized transactions."""

    def __init__(self, path: str | Path | None = None, timeout: float = 5.0) -> None:
        configured_path = path or os.environ.get("CORE_DATABASE_PATH")
        if configured_path is None:
            configured_path = Path.home() / ".canarychain" / "core.sqlite3"
        self.path = str(configured_path) if str(configured_path) == ":memory:" else str(Path(configured_path).expanduser())
        self._lock = threading.RLock()
        self._closed = False

        try:
            if self.path != ":memory:":
                Path(self.path).expanduser().parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(
                self.path,
                timeout=timeout,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            self._initialize()
        except (OSError, sqlite3.Error) as exc:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise CoreDatabaseError("could not initialize core database") from exc
        except CoreDatabaseError:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise CoreDatabaseError("core database is closed")
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                yield self._connection
                self._connection.commit()
            except sqlite3.Error as exc:
                self._connection.rollback()
                raise CoreDatabaseError("core database transaction failed") from exc
            except BaseException:
                self._connection.rollback()
                raise

    def _initialize(self) -> None:
        with self._transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS core_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation TEXT NOT NULL CHECK (operation IN ('attack', 'query', 'defense')),
                    prompt TEXT NOT NULL,
                    result TEXT,
                    status TEXT NOT NULL CHECK (status IN ('completed', 'denied', 'gateway_error')),
                    rule_id TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS defensive_rules (
                    rule_id TEXT PRIMARY KEY,
                    pattern TEXT NOT NULL,
                    description TEXT NOT NULL,
                    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO defensive_rules (rule_id, pattern, description, enabled)
                VALUES (?, ?, ?, ?)
                """,
                (
                    DEFAULT_DEFENSIVE_RULE.rule_id,
                    DEFAULT_DEFENSIVE_RULE.pattern,
                    DEFAULT_DEFENSIVE_RULE.description,
                    int(DEFAULT_DEFENSIVE_RULE.enabled),
                ),
            )

    @staticmethod
    def _core_record(row: sqlite3.Row) -> CoreRecord:
        return CoreRecord(
            id=row["id"],
            operation=row["operation"],
            prompt=row["prompt"],
            result=row["result"],
            status=row["status"],
            rule_id=row["rule_id"],
            created_at=row["created_at"],
        )

    def save_record(
        self,
        operation: str,
        prompt: str,
        result: str | None,
        status: str,
        rule_id: str | None = None,
    ) -> CoreRecord:
        if operation not in _OPERATIONS:
            raise ValueError("unsupported core operation")
        if status not in _STATUSES:
            raise ValueError("unsupported core record status")

        with self._transaction() as connection:
            cursor = connection.execute(
                """
                INSERT INTO core_records (operation, prompt, result, status, rule_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                (operation, prompt, result, status, rule_id),
            )
            row = connection.execute(
                "SELECT * FROM core_records WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
            return self._core_record(row)

    def latest_record(self) -> CoreRecord | None:
        with self._lock:
            if self._closed:
                raise CoreDatabaseError("core database is closed")
            try:
                row = self._connection.execute(
                    "SELECT * FROM core_records ORDER BY id DESC LIMIT 1"
                ).fetchone()
            except sqlite3.Error as exc:
                raise CoreDatabaseError("could not read latest core record") from exc
        return self._core_record(row) if row is not None else None

    def latest_completed_record(self) -> CoreRecord | None:
        with self._lock:
            if self._closed:
                raise CoreDatabaseError("core database is closed")
            try:
                row = self._connection.execute(
                    "SELECT * FROM core_records WHERE status = ? ORDER BY id DESC LIMIT 1",
                    ("completed",),
                ).fetchone()
            except sqlite3.Error as exc:
                raise CoreDatabaseError("could not read latest core result") from exc
        return self._core_record(row) if row is not None else None

    def save_defensive_rule(self, rule: DefensiveRule) -> None:
        try:
            re.compile(rule.pattern)
        except re.error as exc:
            raise ValueError("defensive rule pattern is not a valid regular expression") from exc

        with self._transaction() as connection:
            connection.execute(
                """
                INSERT INTO defensive_rules (rule_id, pattern, description, enabled)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(rule_id) DO UPDATE SET
                    pattern = excluded.pattern,
                    description = excluded.description,
                    enabled = excluded.enabled,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (rule.rule_id, rule.pattern, rule.description, int(rule.enabled)),
            )

    def list_defensive_rules(self, enabled_only: bool = False) -> list[DefensiveRule]:
        with self._lock:
            if self._closed:
                raise CoreDatabaseError("core database is closed")
            try:
                if enabled_only:
                    rows = self._connection.execute(
                        "SELECT rule_id, pattern, description, enabled FROM defensive_rules "
                        "WHERE enabled = ? ORDER BY rule_id",
                        (1,),
                    ).fetchall()
                else:
                    rows = self._connection.execute(
                        "SELECT rule_id, pattern, description, enabled FROM defensive_rules "
                        "ORDER BY rule_id"
                    ).fetchall()
            except sqlite3.Error as exc:
                raise CoreDatabaseError("could not read defensive rules") from exc
        return [
            DefensiveRule(
                rule_id=row["rule_id"],
                pattern=row["pattern"],
                description=row["description"],
                enabled=bool(row["enabled"]),
            )
            for row in rows
        ]

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True


@lru_cache(maxsize=1)
def get_core_database() -> CoreDatabase:
    """Return the process-wide core database used by the API dependencies."""
    return CoreDatabase()
"""Append-only SHA-256 hash chain.

Hash rule (documented in docs/security-contract.md; implemented only here):
    entry_hash = SHA-256(canonical_json(fields) + prev_hash)
    canonical_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    first prev_hash = "GENESIS"
"""

import hashlib
import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from app.db.models_security import AuditEntry
from app.db.security_store import SecurityStore


def canonical_json(fields: dict) -> str:
    """Deterministic serialization used for hashing."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":"))


def compute_entry_hash(fields: dict, prev_hash: str) -> str:
    """Hash of an event's fields chained to the previous entry's hash."""
    return hashlib.sha256((canonical_json(fields) + prev_hash).encode("utf-8")).hexdigest()


def entry_fields(entry: AuditEntry) -> dict:
    """The fields covered by an entry's hash (everything except the hashes)."""
    return {
        "event_id": entry.event_id,
        "timestamp": entry.timestamp,
        "tenant": entry.tenant,
        "event_type": entry.event_type,
        "canary_type": entry.canary_type,
        "atlas_technique": entry.atlas_technique,
        "severity_score": entry.severity_score,
        "details": entry.details,
    }


def utc_now() -> datetime:
    """Current UTC time (injectable in tests)."""
    return datetime.now(UTC)


class AuditChain:
    """Appends events to the store, chaining each to the one before it."""

    def __init__(self, store: SecurityStore, clock: Callable[[], datetime] = utc_now) -> None:
        self._store = store
        self._clock = clock

    def append(
        self,
        tenant: str,
        event_type: str,
        canary_type: str | None,
        atlas_technique: str,
        severity_score: float | None,
        details: dict,
    ) -> AuditEntry:
        """Append one event; the store serializes writers so the chain cannot fork."""
        event_id = str(uuid.uuid4())
        timestamp = self._clock().isoformat(timespec="microseconds")

        def build(prev_hash: str) -> AuditEntry:
            fields = {
                "event_id": event_id,
                "timestamp": timestamp,
                "tenant": tenant,
                "event_type": event_type,
                "canary_type": canary_type,
                "atlas_technique": atlas_technique,
                "severity_score": severity_score,
                "details": details,
            }
            return AuditEntry(**fields, prev_hash=prev_hash, entry_hash=compute_entry_hash(fields, prev_hash))

        return self._store.append_audit(build)

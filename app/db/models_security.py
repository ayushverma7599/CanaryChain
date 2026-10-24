from dataclasses import dataclass


@dataclass(frozen=True)
class AuditEntry:
    """One row of the hash-chained audit log."""

    event_id: str
    timestamp: str
    tenant: str
    event_type: str
    canary_type: str | None
    atlas_technique: str
    severity_score: float | None
    details: dict
    prev_hash: str
    entry_hash: str

"""Walk the audit chain and validate every link and hash."""

from dataclasses import asdict, dataclass

from app.db.security_store import SecurityStore
from app.security.audit_chain import compute_entry_hash, entry_fields
from app.security.constants import GENESIS_HASH


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of a full-chain verification."""

    verified: bool
    checked_entries: int
    first_error_event_id: str | None
    head_hash: str | None

    def to_dict(self) -> dict:
        """JSON-ready form matching GET /verify."""
        return asdict(self)


def verify_chain(store: SecurityStore) -> VerifyResult:
    """Recompute every hash and link; report the first entry that fails.

    head_hash is the entry_hash of the last entry that was checked and passed
    (None for an empty log). Anchor it externally to detect truncation.
    """
    expected_prev = GENESIS_HASH
    checked = 0
    head: str | None = None
    for entry in store.iter_audit():
        checked += 1
        intact = (
            entry.prev_hash == expected_prev
            and entry.entry_hash == compute_entry_hash(entry_fields(entry), entry.prev_hash)
        )
        if not intact:
            return VerifyResult(False, checked, entry.event_id, head)
        expected_prev = head = entry.entry_hash
    return VerifyResult(True, checked, None, head)

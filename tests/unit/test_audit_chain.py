import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from itertools import pairwise

import pytest

from app.db.security_store import SecurityDatabaseError, SecurityStore
from app.security.audit_chain import AuditChain, canonical_json, compute_entry_hash
from app.security.constants import GENESIS_HASH
from app.security.verify_chain import verify_chain


@pytest.fixture
def store(tmp_path):
    return SecurityStore(tmp_path / "security.sqlite3")


@pytest.fixture
def chain(store):
    ticks = (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=n) for n in range(10_000))
    return AuditChain(store, clock=lambda: next(ticks))


def add(chain, n=1):
    return [chain.append("red-team", "policy_block", None, "unmapped", None, {"n": i}) for i in range(n)]


def tamper(store, sql, params=()):
    connection = sqlite3.connect(store.path)
    connection.execute(sql, params)
    connection.commit()
    connection.close()


def test_hash_rule_is_documented_formula():
    fields = {"b": 2, "a": 1}
    assert canonical_json(fields) == '{"a":1,"b":2}'
    import hashlib

    assert compute_entry_hash(fields, "GENESIS") == hashlib.sha256(b'{"a":1,"b":2}GENESIS').hexdigest()


def test_empty_chain_verifies(store):
    result = verify_chain(store)
    assert (result.verified, result.checked_entries, result.head_hash) == (True, 0, None)


def test_valid_chain_verifies_and_reports_head(chain, store):
    entries = add(chain, 5)
    assert entries[0].prev_hash == GENESIS_HASH
    assert all(b.prev_hash == a.entry_hash for a, b in pairwise(entries))
    result = verify_chain(store)
    assert result.verified and result.checked_entries == 5
    assert result.first_error_event_id is None and result.head_hash == entries[-1].entry_hash


def test_edited_entry_fails_and_names_it(chain, store):
    entries = add(chain, 4)
    tamper(store, "UPDATE audit_log SET tenant = 'blue-team' WHERE event_id = ?", (entries[1].event_id,))
    result = verify_chain(store)
    assert not result.verified
    assert result.first_error_event_id == entries[1].event_id
    assert result.head_hash == entries[0].entry_hash


def test_edited_details_fail(chain, store):
    entries = add(chain, 3)
    tamper(store, "UPDATE audit_log SET details = '{\"n\":99}' WHERE event_id = ?", (entries[2].event_id,))
    assert verify_chain(store).first_error_event_id == entries[2].event_id


def test_unparseable_details_fail(chain, store):
    entries = add(chain, 2)
    tamper(store, "UPDATE audit_log SET details = 'not json' WHERE event_id = ?", (entries[0].event_id,))
    assert verify_chain(store).first_error_event_id == entries[0].event_id


def test_deleted_middle_entry_breaks_link(chain, store):
    entries = add(chain, 4)
    tamper(store, "DELETE FROM audit_log WHERE event_id = ?", (entries[1].event_id,))
    result = verify_chain(store)
    assert not result.verified and result.first_error_event_id == entries[2].event_id


def test_deleted_trailing_entry_is_not_detected_without_external_anchor(chain, store):
    """Documented limitation: truncation passes; only an externally saved head_hash catches it."""
    entries = add(chain, 3)
    tamper(store, "DELETE FROM audit_log WHERE event_id = ?", (entries[2].event_id,))
    result = verify_chain(store)
    assert result.verified and result.head_hash == entries[1].entry_hash


def test_concurrent_appends_do_not_fork(chain, store):
    threads = [threading.Thread(target=add, args=(chain, 10)) for _ in range(5)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    result = verify_chain(store)
    assert result.verified and result.checked_entries == 50


def test_duplicate_prev_hash_is_rejected(chain, store):
    first = add(chain, 1)[0]
    with pytest.raises(SecurityDatabaseError):
        store.append_audit(lambda _prev: first.__class__(**{**first.__dict__, "event_id": "other"}))

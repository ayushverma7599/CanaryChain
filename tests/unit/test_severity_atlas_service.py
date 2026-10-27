from datetime import UTC, datetime, timedelta

import pytest

from app.db.security_store import SecurityStore
from app.security.atlas_mapper import AtlasMapper
from app.security.canary_agent import generate_token
from app.security.service import SecurityService
from app.security.severity import SeverityModel


@pytest.mark.parametrize(
    "actor,victim,ctype,repeated,expected",
    [
        ("red-team", "blue-team", "file", True, 0.72),          # 0.9 x 0.8 x 1.0 (the worked example)
        ("blue-team", "red-team", "credential", False, 0.72),   # 0.9 x 1.0 x 0.8
        ("red-team", "client-llm", "credential", False, 0.8),   # 1.0 x 1.0 x 0.8
        ("red-team", "client-llm", "process", True, 0.6),
        ("unknown", "red-team", "network", False, 0.336),       # 0.6 x 0.7 x 0.8
    ],
)
def test_severity_math(actor, victim, ctype, repeated, expected):
    result = SeverityModel().score(actor, victim, ctype, repeated)
    assert result.score == pytest.approx(expected)
    assert set(result.factors) == {"boundary_criticality", "type_weight", "reproducibility"}


def test_severity_rejects_unknown_type():
    with pytest.raises(ValueError):
        SeverityModel().score("red-team", "blue-team", "magic", False)


def test_atlas_defaults_to_unmapped_never_inventing_ids():
    mapper = AtlasMapper()
    assert mapper.lookup("credential_canary_trip") == "unmapped"
    assert mapper.lookup("something_new") == "unmapped"


def test_atlas_uses_only_reviewed_complete_entries():
    mapper = AtlasMapper(
        {
            "a": {"status": "reviewed", "technique_id": "AML.T0000", "technique_name": "Example"},
            "b": {"status": "TODO", "technique_id": "AML.T0001", "technique_name": "Draft"},
            "c": {"status": "reviewed", "technique_id": None, "technique_name": None},
        }
    )
    assert mapper.lookup("a") == "AML.T0000 Example"
    assert mapper.lookup("b") == mapper.lookup("c") == "unmapped"


class Clock:
    def __init__(self):
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self):
        return self.now


@pytest.fixture
def service(tmp_path):
    clock = Clock()
    svc = SecurityService(SecurityStore(tmp_path / "s.sqlite3"), clock=clock)
    svc.clock = clock
    return svc


def trip_event(service, actor="blue-team", ctype="file"):
    return service.record_event("red-team", f"{ctype}_canary_trip", {"actor": actor}, ctype)


def test_canary_event_is_scored_labelled_and_chained(service):
    trip_event(service)
    (entry,) = service.store.list_canary()
    assert entry.severity_score == pytest.approx(0.9 * 0.8 * 0.8)
    assert entry.atlas_technique == "unmapped"
    assert entry.details["severity_factors"] == {"boundary_criticality": 0.9, "type_weight": 0.8, "reproducibility": 0.8}
    assert service.verify().verified


def test_repeat_within_window_scores_higher_then_resets(service):
    trip_event(service)
    service.clock.now += timedelta(seconds=30)
    trip_event(service)
    service.clock.now += timedelta(seconds=120)
    trip_event(service)
    scores = [e.severity_score for e in reversed(service.store.list_canary())]
    assert scores == pytest.approx([0.576, 0.72, 0.576])


def test_non_canary_event_has_null_severity(service):
    service.record_event("red-team", "policy_block", {"rule_id": "x"})
    (entry,) = service.store.list_audit()
    assert entry.severity_score is None and entry.canary_type is None


def test_record_event_validates_inputs(service):
    with pytest.raises(ValueError):
        service.record_event("mallory", "policy_block", {})
    with pytest.raises(ValueError):
        service.record_event("red-team", "x", {}, "magic")


def test_scan_text_returns_event_ids_and_records_trips(service):
    token = generate_token("blue-team")
    ids = service.scan_text("red-team", f"reply containing {token}")
    assert len(ids) == 1
    (entry,) = service.store.list_canary()
    assert entry.event_id == ids[0] and entry.tenant == "blue-team" and entry.details["actor"] == "red-team"
    assert service.scan_text("red-team", "clean reply") == []


def test_shipped_atlas_map_is_well_formed_and_nothing_unreviewed_is_shown():
    import json
    from pathlib import Path

    data = json.loads(Path("app/security/atlas_map.json").read_text(encoding="utf-8"))
    entries = {k: v for k, v in data.items() if not k.startswith("_")}
    assert set(entries) >= {"credential_canary_trip", "file_canary_trip", "network_canary_trip", "process_canary_trip", "policy_block"}
    for event_type, entry in entries.items():
        assert entry["status"] in {"TODO", "proposed", "reviewed"}, event_type
        if entry["status"] != "TODO":
            assert entry["technique_id"].startswith("AML.T") and entry["technique_name"] and entry["tactic"] and entry["sources"], event_type
    mapper = AtlasMapper(data)
    unreviewed = [e for e, v in entries.items() if v["status"] != "reviewed"]
    assert all(mapper.lookup(e) == "unmapped" for e in unreviewed)

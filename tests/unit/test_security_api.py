import sqlite3
from importlib import util
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.security import router
from app.db.security_store import SecurityDatabaseError, SecurityStore
from app.security.canary_agent import generate_token
from app.security.service import SecurityService, get_security_service

TOKEN = "test-internal-token"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("INTERNAL_EVENT_TOKEN", TOKEN)
    service = SecurityService(SecurityStore(tmp_path / "s.sqlite3"))
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_security_service] = lambda: service
    return TestClient(app), service


def post_event(client, token=TOKEN, **overrides):
    body = {"tenant": "red-team", "event_type": "file_canary_trip", "canary_type": "file", "details": {"actor": "blue-team"}}
    body.update(overrides)
    headers = {} if token is None else {"X-Internal-Token": token}
    return client.post("/internal/event", json=body, headers=headers)


def test_empty_endpoints_return_empty_lists_and_verified(env):
    client, _ = env
    assert client.get("/audit").json() == {"items": []}
    assert client.get("/canary").json() == {"items": []}
    assert client.get("/verify").json() == {"verified": True, "checked_entries": 0, "first_error_event_id": None, "head_hash": None}


def test_contract_fields_for_audit_and_canary(env):
    client, service = env
    service.scan_text("red-team", generate_token("blue-team"))
    service.record_event("red-team", "policy_block", {"rule_id": "r"})
    audit = client.get("/audit").json()["items"]
    assert [i["event_type"] for i in audit] == ["policy_block", "credential_canary_trip"]
    assert set(audit[0]) == {"event_id", "timestamp", "tenant", "actor", "event_type", "atlas_technique", "severity_score", "entry_hash"}
    assert audit[0]["actor"] is None  # a policy_block has no actor
    assert audit[1]["actor"] == "red-team"  # who received blue's token
    canary = client.get("/canary").json()["items"]
    assert len(canary) == 1 and canary[0]["canary_type"] == "credential"
    assert set(canary[0]) == {"event_id", "timestamp", "tenant", "actor", "canary_type", "atlas_technique", "severity_score"}
    assert (canary[0]["tenant"], canary[0]["actor"]) == ("blue-team", "red-team")
    assert canary[0]["atlas_technique"] == "unmapped" and canary[0]["severity_score"] == pytest.approx(0.72)


def test_verify_detects_tampering_end_to_end(env):
    client, service = env
    ids = [service.record_event("red-team", "policy_block", {"n": n}) for n in range(3)]
    assert client.get("/verify").json()["verified"] is True
    connection = sqlite3.connect(service.store.path)
    connection.execute("UPDATE audit_log SET tenant = 'blue-team' WHERE event_id = ?", (ids[0],))
    connection.commit()
    connection.close()
    body = client.get("/verify").json()
    assert body["verified"] is False and body["first_error_event_id"] == ids[0]


def test_internal_event_requires_valid_token(env):
    client, service = env
    assert post_event(client, token=None).status_code == 401
    assert post_event(client, token="wrong").status_code == 401
    assert service.store.list_audit() == []
    ok = post_event(client)
    assert ok.status_code == 201 and ok.json()["event_id"]
    assert len(client.get("/canary").json()["items"]) == 1


def test_internal_event_fails_closed_without_configured_token(env, monkeypatch):
    client, _ = env
    monkeypatch.delenv("INTERNAL_EVENT_TOKEN")
    response = post_event(client)
    assert response.status_code == 503 and response.json()["error"]["code"] == "internal_events_disabled"


def test_internal_event_validation(env):
    client, _ = env
    assert post_event(client, tenant="mallory").status_code == 422
    assert post_event(client, canary_type="magic").status_code == 422


def test_store_failure_returns_error_body_not_a_crash(env):
    client, service = env

    def boom(*_a, **_k):
        raise SecurityDatabaseError("down")

    service.store.list_audit = boom
    response = client.get("/audit")
    assert response.status_code == 503 and response.json()["error"]["code"] == "security_store_unavailable"


def test_gateway_reports_only_tenant_to_tenant_leaks():
    path = Path(__file__).resolve().parents[2] / "gateway" / "gateway.py"
    spec = util.spec_from_file_location("gateway_module", path)
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    leak = {"actor": "red", "path": "/llm/v1/chat", "tokens_seen": ["blue", "red"]}
    (event,) = module.collector_events(leak)
    assert event["tenant"] == "blue-team" and event["details"]["actor"] == "red-team"
    assert module.collector_events({"actor": "host", "tokens_seen": ["blue"]}) == []
    assert module.collector_events({"actor": "red", "tokens_seen": []}) == []

import pytest
from fastapi.testclient import TestClient

from app.api.routes.core import get_llm_client
from app.db.database import CoreDatabase, get_core_database
from app.main import app
from app.security.service import get_security_service


class StubLLM:
    def __init__(self) -> None:
        self.prompts: list[str] = []

    def generate(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return "stub response"


@pytest.fixture
def env(tmp_path):
    llm = StubLLM()
    database = CoreDatabase(tmp_path / "core.sqlite3")
    app.dependency_overrides[get_llm_client] = lambda: llm
    app.dependency_overrides[get_core_database] = lambda: database
    with TestClient(app) as client:
        yield client, llm
    app.dependency_overrides.clear()
    database.close()


def save(client, **body):
    payload = {"name": "Block Zebra", "rule": "zebra", "enabled": True}
    payload.update(body)
    return client.post("/defense", json=payload)


def test_saved_rule_is_applied_to_the_next_attack(env):
    client, llm = env
    response = save(client)
    assert response.status_code == 200
    assert response.json() == {"rule_id": "block-zebra", "status": "saved"}

    denied = client.post("/attack", json={"prompt": "Tell me about a ZEBRA"})
    assert denied.status_code == 403
    assert denied.json()["rule_id"] == "block-zebra"
    assert denied.json()["message"] == "Denied by defense rule \u201cBlock Zebra\u201d."
    assert llm.prompts == []  # the LLM was never called


def test_saving_the_same_name_updates_the_rule_and_can_disable_it(env):
    client, llm = env
    save(client)
    assert save(client, rule="giraffe").json()["rule_id"] == "block-zebra"  # same name -> same rule, updated
    assert client.post("/attack", json={"prompt": "a zebra"}).status_code == 200
    assert client.post("/attack", json={"prompt": "a giraffe"}).status_code == 403

    assert save(client, rule="giraffe", enabled=False).status_code == 200
    assert client.post("/attack", json={"prompt": "a giraffe"}).status_code == 200
    assert len(llm.prompts) == 2


@pytest.mark.parametrize(
    "overrides",
    [
        {"rule": "[unclosed"},          # not a valid regular expression
        {"rule": "(a+)+"},              # catastrophic-backtracking shape
        {"rule": "x" * 201},            # too long
        {"name": "!!!"},                # no letters or digits to build an id from
        {"name": "   "},
        {"rule": "   "},
    ],
)
def test_invalid_rules_are_rejected_and_not_stored(env, overrides):
    client, _ = env
    assert save(client, **overrides).status_code == 422
    assert client.post("/attack", json={"prompt": "zebra"}).status_code == 200  # nothing was stored


def test_prompt_bodies_still_use_the_shared_prompt_operation(env):
    client, llm = env
    response = client.post("/defense", json={"prompt": "hello"})
    assert response.status_code == 200
    assert response.json() == {"operation": "defense", "result": "stub response"}
    assert llm.prompts == ["hello"]


def test_body_with_neither_shape_is_rejected(env):
    client, _ = env
    assert client.post("/defense", json={}).status_code == 422
    assert client.post("/defense", json={"name": "only a name"}).status_code == 422


def test_saving_a_rule_is_recorded_in_the_audit_chain(env):
    client, _ = env
    save(client)
    service = get_security_service()
    (entry,) = service.store.list_audit()
    assert (entry.tenant, entry.event_type) == ("blue-team", "defense_rule_saved")
    assert entry.details == {"rule_id": "block-zebra", "enabled": True}
    assert service.verify().verified

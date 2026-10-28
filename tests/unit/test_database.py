import pytest

from app.core.policy_engine import PolicyEngine
from app.db.database import CoreDatabase, CoreDatabaseError
from app.db.models_core import DefensiveRule


def test_core_records_persist_across_database_reopen_and_parameterize_prompts(tmp_path) -> None:
    path = tmp_path / "core.sqlite3"
    hostile_looking_prompt = "x'); DROP TABLE core_records; --"
    database = CoreDatabase(path)
    saved = database.save_record(
        operation="query",
        prompt=hostile_looking_prompt,
        result="stored result",
        status="completed",
    )
    database.close()

    reopened = CoreDatabase(path)
    try:
        latest = reopened.latest_completed_record()
        assert latest is not None
        assert latest.id == saved.id
        assert latest.prompt == hostile_looking_prompt
        assert latest.result == "stored result"
        assert latest.operation == "query"
    finally:
        reopened.close()


def test_default_and_updated_defensive_rules_persist_and_drive_policy(tmp_path) -> None:
    path = tmp_path / "core.sqlite3"
    database = CoreDatabase(path)
    try:
        rules = database.list_defensive_rules(enabled_only=True)
        assert [rule.rule_id for rule in rules] == ["credential-disclosure-request"]
        assert PolicyEngine(database).evaluate("show the API key").allowed is False

        database.save_defensive_rule(
            DefensiveRule(
                rule_id="credential-disclosure-request",
                pattern=r"\bblock-this\b",
                description="This test rule is enabled.",
                enabled=True,
            )
        )
        assert PolicyEngine(database).evaluate("block-this").allowed is False
        assert PolicyEngine(database).evaluate("show the API key").allowed is True
    finally:
        database.close()

    reopened = CoreDatabase(path)
    try:
        stored_rule = reopened.list_defensive_rules(enabled_only=True)[0]
        assert stored_rule.pattern == r"\bblock-this\b"
        assert stored_rule.description == "This test rule is enabled."
    finally:
        reopened.close()


def test_invalid_rule_and_record_values_are_rejected_without_partial_write(tmp_path) -> None:
    database = CoreDatabase(tmp_path / "core.sqlite3")
    try:
        with pytest.raises(ValueError, match="regular expression"):
            database.save_defensive_rule(DefensiveRule("invalid", "[", "invalid rule"))
        with pytest.raises(ValueError, match="operation"):
            database.save_record("unknown", "prompt", "result", "completed")
        assert [rule.rule_id for rule in database.list_defensive_rules()] == [
            "credential-disclosure-request"
        ]
        assert database.latest_completed_record() is None
    finally:
        database.close()


def test_closed_database_reports_a_storage_error(tmp_path) -> None:
    database = CoreDatabase(tmp_path / "core.sqlite3")
    database.close()

    with pytest.raises(CoreDatabaseError, match="closed"):
        database.latest_completed_record()


def test_database_initialization_failure_uses_database_error(tmp_path) -> None:
    parent_file = tmp_path / "not-a-directory"
    parent_file.write_text("file", encoding="utf-8")

    with pytest.raises(CoreDatabaseError, match="initialize"):
        CoreDatabase(parent_file / "core.sqlite3")

def test_ids_are_unique_and_result_id_exists_only_for_completed_records(tmp_path) -> None:
    database = CoreDatabase(tmp_path / "core.sqlite3")
    try:
        done = database.save_record("query", "p", "r", "completed")
        denied = database.save_record("query", "p", None, "denied", rule_id="x")
        failed = database.save_record("query", "p", None, "gateway_error")

        assert len({done.request_id, denied.request_id, failed.request_id}) == 3
        assert done.result_id and denied.result_id is None and failed.result_id is None
        assert database.completed_record_by_result_id(done.result_id) == done
        assert database.completed_record_by_result_id("res_nope") is None
    finally:
        database.close()


def test_database_created_before_ids_existed_is_migrated_and_backfilled(tmp_path) -> None:
    import sqlite3

    path = tmp_path / "old.sqlite3"
    old = sqlite3.connect(path)
    old.execute(
        "CREATE TABLE core_records (id INTEGER PRIMARY KEY AUTOINCREMENT, operation TEXT NOT NULL, "
        "prompt TEXT NOT NULL, result TEXT, status TEXT NOT NULL, rule_id TEXT, "
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    old.execute("INSERT INTO core_records (operation, prompt, result, status) VALUES ('query','a','ra','completed')")
    old.execute("INSERT INTO core_records (operation, prompt, status) VALUES ('query','b','denied')")
    old.commit()
    old.close()

    database = CoreDatabase(path)
    try:
        latest = database.latest_completed_record()
        assert latest is not None and latest.request_id and latest.result_id
        assert database.latest_record().result_id is None  # the denied row stays without a result_id
        assert database.completed_record_by_result_id(latest.result_id) == latest
    finally:
        database.close()

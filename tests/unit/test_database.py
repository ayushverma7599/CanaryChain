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
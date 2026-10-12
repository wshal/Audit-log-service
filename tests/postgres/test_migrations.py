import pytest
import re
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from app.storage.database import initialize_ledger_state, run_migrations


def test_postgres_fresh_migration_and_constraints(postgres_engine):
    run_migrations(postgres_engine)
    inspector = inspect(postgres_engine)
    tables = set(inspector.get_table_names())
    assert {"audit_records", "audit_epoch_transitions", "ledger_state", "alembic_version"}.issubset(tables)

    audit_columns = {column["name"]: column for column in inspector.get_columns("audit_records")}
    assert {"sequence_num", "payload_json", "content_hash", "prev_hash", "record_hash", "protocol_version"}.issubset(audit_columns)
    assert audit_columns["sequence_num"]["nullable"] is False
    assert audit_columns["record_hash"]["nullable"] is False

    unique_constraints = inspector.get_unique_constraints("audit_records")
    indexes = inspector.get_indexes("audit_records")
    unique_columns = [set(item.get("column_names") or ()) for item in unique_constraints]
    unique_columns.extend(set(item.get("column_names") or ()) for item in indexes if item.get("unique"))
    assert {"sequence_num"} in unique_columns

    state_columns = {column["name"]: column for column in inspector.get_columns("ledger_state")}
    assert {"singleton_id", "next_sequence", "tip_hash", "state_version"} == set(state_columns)
    checks = inspector.get_check_constraints("ledger_state")
    check_names = {item.get("name") for item in checks}
    assert {
        "ck_ledger_state_singleton",
        "ck_ledger_state_next_sequence",
        "ck_ledger_state_tip_hash_length",
        "ck_ledger_state_version",
    }.issubset(check_names)
    tip_check = next(item for item in checks if item.get("name") == "ck_ledger_state_tip_hash_length")
    reflected_tip_sql = re.sub(r"[\s\"'`()\[\]]", "", str(tip_check.get("sqltext") or "").lower())
    assert "tip_hash" in reflected_tip_sql
    assert "64" in reflected_tip_sql
    assert any(function in reflected_tip_sql for function in ("length", "char_length", "octet_length"))

    with postgres_engine.connect() as connection:
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0002_idempotency_records"
        assert connection.execute(text("SELECT COUNT(*) FROM audit_records")).scalar_one() == 0


def test_postgres_ledger_state_initialization_is_empty_and_non_destructive(postgres_engine):
    run_migrations(postgres_engine)
    initialize_ledger_state(postgres_engine)
    with postgres_engine.connect() as connection:
        state = connection.execute(text("SELECT singleton_id, next_sequence, tip_hash, state_version FROM ledger_state")).one()
        assert tuple(state) == (1, 1, "0" * 64, 1)
        assert connection.execute(text("SELECT COUNT(*) FROM audit_records")).scalar_one() == 0


def test_postgres_migration_is_repeatable(postgres_engine):
    run_migrations(postgres_engine)
    run_migrations(postgres_engine)
    with postgres_engine.connect() as connection:
        assert connection.execute(text("SELECT COUNT(*) FROM audit_records")).scalar_one() == 0


def test_postgres_constraints_reject_invalid_values(postgres_engine):
    run_migrations(postgres_engine)
    with postgres_engine.begin() as connection:
        connection.execute(text("INSERT INTO ledger_state (singleton_id, next_sequence, tip_hash, state_version) VALUES (1, 1, :tip, 1)"), {"tip": "0" * 64})

    with pytest.raises(IntegrityError):
        with postgres_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO ledger_state (singleton_id, next_sequence, tip_hash, state_version) "
                    "VALUES (1, 1, :tip, 1)"
                ),
                {"tip": "0" * 64},
            )

    with pytest.raises(IntegrityError):
        with postgres_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO ledger_state (singleton_id, next_sequence, tip_hash, state_version) "
                    "VALUES (2, 1, :tip, 1)"
                ),
                {"tip": "0" * 64},
            )

    violations = [
        "UPDATE ledger_state SET next_sequence = 0 WHERE singleton_id = 1",
        "UPDATE ledger_state SET tip_hash = 'bad' WHERE singleton_id = 1",
        "UPDATE ledger_state SET state_version = 0 WHERE singleton_id = 1",
    ]
    for statement in violations:
        with pytest.raises(IntegrityError):
            with postgres_engine.begin() as connection:
                connection.execute(text(statement))

    with postgres_engine.begin() as connection:
        connection.execute(text("INSERT INTO audit_records (sequence_num, event_type, actor_id, resource_type, resource_id, payload_json, timestamp, content_hash, prev_hash, record_hash, is_archived, protocol_version) VALUES (1, 'TEST', 'actor', 'CLIENT', 'client-1', '{}', '2026-01-01T00:00:00Z', :hash, :hash, :hash, false, 1)"), {"hash": "0" * 64})
    with pytest.raises(IntegrityError):
        with postgres_engine.begin() as connection:
            connection.execute(text("INSERT INTO audit_records (sequence_num, event_type, actor_id, resource_type, resource_id, payload_json, timestamp, content_hash, prev_hash, record_hash, is_archived, protocol_version) VALUES (1, 'TEST2', 'actor', 'CLIENT', 'client-2', '{}', '2026-01-01T00:00:01Z', :hash, :hash, :hash, false, 1)"), {"hash": "1" * 64})

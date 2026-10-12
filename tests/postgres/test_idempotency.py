import hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from alembic.command import upgrade
from alembic.config import Config
from sqlalchemy import event, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.crypto.hasher import canonical_json
from app.models.schemas import AuditEventCreate
from app.security import Principal
from app.runtime_state import set_state
from app.storage.database import AuditRecordEntity, IdempotencyRecordEntity, LedgerStateEntity, initialize_ledger_state, run_migrations
from app.storage.repository import AuditLedgerRepository, IdempotencyCommitUnknown


def _event() -> AuditEventCreate:
    return AuditEventCreate(
        eventType="POSTGRES_IDEMPOTENT",
        actorId="writer",
        resourceType="TEST",
        resourceId="resource-1",
        payload={"ok": True},
        timestamp="2026-10-07T02:00:00Z",
    )


def _principal() -> Principal:
    return Principal("writer", frozenset({"writer"}), "postgres-idempotency", (), False, True)


def _fingerprint(event_in: AuditEventCreate) -> str:
    material = {
        "eventType": event_in.eventType, "actorId": event_in.actorId,
        "resourceType": event_in.resourceType, "resourceId": event_in.resourceId,
        "payload": event_in.payload, "timestamp": event_in.timestamp,
        "tenantId": event_in.tenantId, "impersonatedActorId": event_in.impersonatedActorId,
        "delegationReason": event_in.delegationReason,
    }
    return hashlib.sha256(canonical_json(material).encode()).hexdigest()


def _upgrade_to(engine, revision: str) -> None:
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        upgrade(config, revision)


def test_postgres_idempotency_constraints(postgres_engine):
    run_migrations(postgres_engine)
    with postgres_engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO audit_records (sequence_num, event_type, actor_id, resource_type, resource_id, payload_json, timestamp, content_hash, prev_hash, record_hash, is_archived, protocol_version) "
            "VALUES (1, 'TEST', 'writer', 'TEST', 'resource-1', '{}', '2026-01-01T00:00:00Z', :hash, :hash, :hash, false, 1)"
        ), {"hash": "0" * 64})
        connection.execute(text(
            "INSERT INTO idempotency_records (scope_principal, scope_tenant, scope_method, scope_endpoint, idempotency_key, request_fingerprint, audit_record_id, created_at, expires_at) "
            "VALUES ('writer', '__legacy__', 'POST', '/audit/events', 'constraint-key', :fingerprint, 1, '2026-01-01T00:00:00Z', '2099-01-01T00:00:00Z')"
        ), {"fingerprint": "a" * 64})

    with pytest.raises(IntegrityError):
        with postgres_engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO idempotency_records (scope_principal, scope_tenant, scope_method, scope_endpoint, idempotency_key, request_fingerprint, audit_record_id, created_at, expires_at) "
                "VALUES ('writer', '__legacy__', 'POST', '/audit/events', 'constraint-key', :fingerprint, 1, '2026-01-01T00:00:00Z', '2099-01-01T00:00:00Z')"
            ), {"fingerprint": "b" * 64})
    with pytest.raises(IntegrityError):
        with postgres_engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO idempotency_records (scope_principal, scope_tenant, scope_method, scope_endpoint, idempotency_key, request_fingerprint, audit_record_id, created_at, expires_at) "
                "VALUES ('other', '__legacy__', 'POST', '/audit/events', 'foreign-key-key', :fingerprint, 9999, '2026-01-01T00:00:00Z', '2099-01-01T00:00:00Z')"
            ), {"fingerprint": "c" * 64})


def test_postgres_upgrade_from_foundation_preserves_audit_data(postgres_engine):
    _upgrade_to(postgres_engine, "0001_schema_foundation")
    original = (1, "{}", "0" * 64, "2026-01-01T00:00:00Z")
    with postgres_engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO audit_records (sequence_num, event_type, actor_id, resource_type, resource_id, payload_json, timestamp, content_hash, prev_hash, record_hash, is_archived, protocol_version) "
            "VALUES (:sequence, 'TEST', 'writer', 'TEST', 'resource-1', :payload, :timestamp, :hash, :hash, :hash, false, 1)"
        ), {"sequence": original[0], "payload": original[1], "timestamp": original[3], "hash": original[2]})
        # The historical 0001 bootstrap currently includes metadata for later
        # models. Remove only the new table so this test exercises revision 0002
        # creating it from a genuine 0001-stamped database.
        connection.execute(text("DROP TABLE idempotency_records"))
    _upgrade_to(postgres_engine, "head")
    inspector = inspect(postgres_engine)
    assert "idempotency_records" in inspector.get_table_names()
    assert {"uq_idempotency_scope_key"} == {item["name"] for item in inspector.get_unique_constraints("idempotency_records")}
    foreign_keys = inspector.get_foreign_keys("idempotency_records")
    assert any(fk["referred_table"] == "audit_records" and fk["constrained_columns"] == ["audit_record_id"] for fk in foreign_keys)
    with postgres_engine.connect() as connection:
        preserved = connection.execute(text("SELECT sequence_num, payload_json, prev_hash, timestamp FROM audit_records")).one()
        revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    assert tuple(preserved) == original
    assert revision == "0002_idempotency_records"


def test_postgres_concurrent_equivalent_requests_append_once(postgres_engine, monkeypatch):
    set_state("healthy")
    run_migrations(postgres_engine)
    initialize_ledger_state(postgres_engine)
    event_in = _event()
    principal = _principal()
    fingerprint = _fingerprint(event_in)

    def worker():
        Session = sessionmaker(autocommit=False, autoflush=False, bind=postgres_engine)
        session = Session()
        try:
            return AuditLedgerRepository(session).append_event_idempotent(
                event_in, principal, scope_principal="postgres-idempotency",
                scope_tenant="__legacy__", scope_method="POST", scope_endpoint="/audit/events",
                idempotency_key="concurrent-key", request_fingerprint=fingerprint,
            )[1]
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: worker(), range(2)))
    assert sorted(results) == [False, True]
    Session = sessionmaker(bind=postgres_engine)
    session = Session()
    try:
        assert session.query(AuditRecordEntity).count() == 1
        assert session.query(IdempotencyRecordEntity).count() == 1
    finally:
        session.close()


def test_postgres_idempotency_rollback_leaves_no_partial_rows(postgres_engine):
    set_state("healthy")
    run_migrations(postgres_engine)
    event_in = _event()
    principal = _principal()
    fingerprint = _fingerprint(event_in)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=postgres_engine)
    session = Session()
    failed = {"value": False}

    def fail_once(current_session, flush_context, instances):
        if not failed["value"]:
            failed["value"] = True
            raise RuntimeError("injected idempotency flush failure")

    event.listen(session, "before_flush", fail_once)
    try:
        with pytest.raises(RuntimeError, match="injected idempotency flush failure"):
            AuditLedgerRepository(session).append_event_idempotent(
                event_in, principal, scope_principal="postgres-idempotency",
                scope_tenant="__legacy__", scope_method="POST", scope_endpoint="/audit/events",
                idempotency_key="rollback-key", request_fingerprint=fingerprint,
            )
    finally:
        event.remove(session, "before_flush", fail_once)
    assert session.query(AuditRecordEntity).count() == 0
    assert session.query(IdempotencyRecordEntity).count() == 0
    session.close()


def test_postgres_ambiguous_commit_replays_durable_result(postgres_engine, monkeypatch, tmp_path):
    set_state("healthy")
    monkeypatch.setenv("AUDIT_DEVELOPMENT_KEY_PATH", str(tmp_path / "signing.key"))
    run_migrations(postgres_engine)
    initialize_ledger_state(postgres_engine)
    event_in = _event()
    principal = _principal()
    fingerprint = _fingerprint(event_in)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=postgres_engine)
    session = Session()
    original_commit = session.commit

    def commit_then_fail():
        original_commit()
        raise OSError("connection lost after PostgreSQL commit")

    monkeypatch.setattr(session, "commit", commit_then_fail)
    with pytest.raises(IdempotencyCommitUnknown):
        AuditLedgerRepository(session).append_event_idempotent(
            event_in, principal, scope_principal="postgres-idempotency",
            scope_tenant="__legacy__", scope_method="POST", scope_endpoint="/audit/events",
            idempotency_key="ambiguous-key", request_fingerprint=fingerprint,
        )
    session.close()

    retry_session = Session()
    try:
        record, replayed = AuditLedgerRepository(retry_session).append_event_idempotent(
            event_in, principal, scope_principal="postgres-idempotency",
            scope_tenant="__legacy__", scope_method="POST", scope_endpoint="/audit/events",
            idempotency_key="ambiguous-key", request_fingerprint=fingerprint,
        )
        assert replayed is True
        assert record.sequence_num == 1
        assert retry_session.query(AuditRecordEntity).count() == 1
        assert retry_session.query(IdempotencyRecordEntity).count() == 1
        state = retry_session.query(LedgerStateEntity).one()
        assert state.next_sequence == 2
    finally:
        retry_session.close()

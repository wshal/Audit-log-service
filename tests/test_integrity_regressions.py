"""Regression tests for integrity boundaries not covered by the happy paths."""

from concurrent.futures import ThreadPoolExecutor
import pytest

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.models.schemas import AuditEventCreate, ViolationType
from app.storage.database import AuditRecordEntity, Base, LedgerStateEntity, initialize_ledger_state
from app.storage.repository import AuditLedgerRepository
from app.security import Principal
from app.crypto.hasher import GENESIS_PREV_HASH
from app.services.verifier import ChainVerificationService
from app.services.lifecycle import LifecycleAndExportService
from app.runtime_state import preflight_scope


def test_redacted_record_mutation_is_detected(client, db_session):
    created = client.post(
        "/audit/events",
        json={
            "eventType": "CLIENT_CREATED", "actorId": "advisor-7",
            "resourceType": "CLIENT", "resourceId": "client-7",
            "payload": {"name": "Ava", "ssn": "123-45-6789"},
            "delegationReason": "integrity fixture ingestion",
            "timestamp": "2026-10-07T12:00:00Z",
        },
    )
    assert created.status_code == 201
    redacted = client.post(
        "/audit/redact",
        json={"sequenceNum": 1, "fieldPaths": ["ssn"], "reason": "Privacy request"},
    )
    assert redacted.status_code == 200
    assert client.get("/audit/verify").json()["intact"] is True

    # Simulate a datastore attacker changing a non-redacted business field after
    # a legal redaction. The immutable redaction manifest must expose it.
    record = db_session.query(AuditRecordEntity).filter_by(sequence_num=1).one()
    record.payload_json = '{"name":"Mallory","ssn":"' + record.to_read_model()["payload"]["ssn"] + '"}'
    db_session.commit()

    result = client.get("/audit/verify").json()
    assert result["intact"] is False
    assert result["firstBrokenSequence"] == 1
    assert result["violationType"] == ViolationType.CONTENT_HASH_MISMATCH.value


def test_redaction_rejects_unknown_or_duplicate_fields(client):
    client.post(
        "/audit/events",
        json={
            "eventType": "CLIENT_CREATED", "actorId": "advisor-7",
            "resourceType": "CLIENT", "resourceId": "client-7",
            "payload": {"ssn": "123-45-6789"},
            "delegationReason": "integrity fixture ingestion",
            "timestamp": "2026-10-07T12:00:00Z",
        },
    )
    unknown = client.post(
        "/audit/redact",
        json={"sequenceNum": 1, "fieldPaths": ["doesNotExist"], "reason": "Privacy request"},
    )
    assert unknown.status_code == 422

    assert client.post(
        "/audit/redact",
        json={"sequenceNum": 1, "fieldPaths": ["ssn"], "reason": "Privacy request"},
    ).status_code == 200
    duplicate = client.post(
        "/audit/redact",
        json={"sequenceNum": 1, "fieldPaths": ["ssn"], "reason": "Privacy request"},
    )
    assert duplicate.status_code == 422

    duplicate_in_one_request = client.post(
        "/audit/redact",
        json={"sequenceNum": 1, "fieldPaths": ["ssn", "ssn"], "reason": "Privacy request"},
    )
    assert duplicate_in_one_request.status_code == 422


def test_timestamps_are_normalized_and_invalid_ranges_are_rejected(client):
    response = client.post(
        "/audit/events",
        json={
            "eventType": "LOGIN", "actorId": "user", "resourceType": "SESSION", "resourceId": "1",
            "payload": {}, "delegationReason": "integrity fixture ingestion", "timestamp": "2026-10-07T12:00:00+05:30",
        },
    )
    assert response.status_code == 201
    assert response.json()["timestamp"] == "2026-10-07T06:30:00Z"
    server_timestamp = client.post(
        "/audit/events",
        json={"eventType": "LOGIN", "actorId": "user", "resourceType": "SESSION", "resourceId": "2", "payload": {}, "delegationReason": "integrity fixture ingestion"},
    ).json()["timestamp"]
    assert server_timestamp.endswith("Z")
    assert client.get("/audit/events?fromTime=2026-10-08T00:00:00Z&toTime=2026-10-07T00:00:00Z").status_code == 422
    assert client.get("/audit/events?fromTime=not-a-time").status_code == 422


def test_sqlite_append_serializes_competing_writers(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'ledger.db'}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(autoflush=False, bind=engine)

    def append(index):
        session = session_factory()
        try:
            return AuditLedgerRepository(session).append_event(AuditEventCreate(
                eventType="CONCURRENT_WRITE", actorId=str(index), resourceType="TEST",
                resourceId=str(index), payload={}, delegationReason="integrity fixture ingestion", timestamp="2026-10-07T00:00:00Z",
            ), Principal(str(index), frozenset({"writer"}), "concurrency", (), True)).sequence_num
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=8) as executor:
        sequence_numbers = list(executor.map(append, range(24)))

    assert sorted(sequence_numbers) == list(range(1, 25))
    session = session_factory()
    try:
        records = session.query(AuditRecordEntity).order_by(AuditRecordEntity.sequence_num.asc()).all()
        assert len(records) == 24
        assert [record.sequence_num for record in records] == list(range(1, 25))
        assert len({record.sequence_num for record in records}) == 24
        assert records[0].prev_hash == GENESIS_PREV_HASH
        for previous, current in zip(records, records[1:]):
            assert current.prev_hash == previous.record_hash
        with preflight_scope():
            result = ChainVerificationService.verify_ledger(
                session,
                principal=Principal("global-auditor", frozenset({"global_auditor"}), "audit", (), True),
            )
        assert result.intact is True
    finally:
        session.close()


def test_allocator_rejects_dirty_transaction_before_lock(db_session):
    db_session.add(LedgerStateEntity(singleton_id=99, next_sequence=1, tip_hash=GENESIS_PREV_HASH, state_version=1))
    with pytest.raises(RuntimeError, match="explicitly ended caller transaction"):
        AuditLedgerRepository.lock_ledger_state(db_session)
    db_session.rollback()
    assert db_session.query(LedgerStateEntity).count() == 0


def test_allocator_rejects_read_only_transaction_without_rollback(db_session):
    db_session.execute(text("SELECT 1"))
    with pytest.raises(RuntimeError, match="explicitly ended caller transaction"):
        AuditLedgerRepository.lock_ledger_state(db_session)
    assert db_session.in_transaction()
    db_session.rollback()


def test_allocator_rejects_core_sql_transaction_without_rollback(db_session):
    AuditLedgerRepository(db_session).append_event(_event(1), _writer())
    db_session.rollback()
    before = db_session.query(LedgerStateEntity).one().state_version
    db_session.rollback()
    db_session.execute(text("UPDATE ledger_state SET state_version = state_version + 1 WHERE singleton_id = 1"))
    with pytest.raises(RuntimeError, match="explicitly ended caller transaction"):
        AuditLedgerRepository.lock_ledger_state(db_session)
    assert db_session.in_transaction()
    assert not db_session.new and not db_session.dirty and not db_session.deleted
    db_session.rollback()
    assert db_session.query(LedgerStateEntity).one().state_version == before


def test_lifecycle_journal_requires_allocator_lock(db_session):
    with pytest.raises(RuntimeError, match="requires an acquired ledger allocator lock"):
        LifecycleAndExportService._append_lifecycle_journal(
            db_session, "AUDIT_RECORD_ARCHIVED", "record-1", {}, tenant_id=None
        )


def _writer(subject="writer"):
    return Principal(subject, frozenset({"writer"}), subject, (), True)


def _event(sequence_label):
    return AuditEventCreate(
        eventType="STATE_TEST",
        actorId="writer",
        resourceType="TEST",
        resourceId=str(sequence_label),
        payload={"label": sequence_label},
        delegationReason="allocator test",
        timestamp=f"2026-10-07T00:00:{sequence_label:02d}Z",
    )


def test_empty_ledger_initializes_state_and_first_append(db_session):
    record = AuditLedgerRepository(db_session).append_event(_event(1), _writer())
    state = db_session.query(LedgerStateEntity).one()
    assert record.sequence_num == 1
    assert record.prev_hash == GENESIS_PREV_HASH
    assert state.next_sequence == 2
    assert state.tip_hash == record.record_hash


def test_populated_ledger_without_state_requires_explicit_initialization(db_session):
    first = AuditLedgerRepository(db_session).append_event(_event(1), _writer())
    db_session.query(LedgerStateEntity).delete()
    db_session.commit()

    with pytest.raises(RuntimeError, match="missing for a populated ledger"):
        AuditLedgerRepository(db_session).append_event(_event(2), _writer())
    initialize_ledger_state(db_session.bind)
    second = AuditLedgerRepository(db_session).append_event(_event(2), _writer())
    state = db_session.query(LedgerStateEntity).one()
    assert second.sequence_num == 2
    assert second.prev_hash == first.record_hash
    assert state.next_sequence == 3
    assert state.tip_hash == second.record_hash


def test_startup_state_initialization_derives_valid_populated_ledger(db_session):
    first = AuditLedgerRepository(db_session).append_event(_event(1), _writer())
    db_session.query(LedgerStateEntity).delete()
    db_session.commit()

    initialize_ledger_state(db_session.bind)
    state = db_session.query(LedgerStateEntity).one()
    assert (state.next_sequence, state.tip_hash) == (2, first.record_hash)


def test_startup_state_initialization_rejects_invalid_history(db_session):
    first = AuditLedgerRepository(db_session).append_event(_event(1), _writer())
    record = db_session.query(AuditRecordEntity).one()
    record.payload_json = '{"tampered":true}'
    db_session.query(LedgerStateEntity).delete()
    db_session.commit()

    with pytest.raises(RuntimeError, match="invalid audit history"):
        initialize_ledger_state(db_session.bind)
    assert db_session.query(LedgerStateEntity).count() == 0
    assert db_session.query(AuditRecordEntity).one().record_hash == first.record_hash


def test_inconsistent_ledger_state_rejects_append_without_mutation(db_session):
    first = AuditLedgerRepository(db_session).append_event(_event(1), _writer())
    state = db_session.query(LedgerStateEntity).one()
    state.tip_hash = "f" * 64
    db_session.commit()

    with pytest.raises(RuntimeError, match="Ledger state does not match"):
        AuditLedgerRepository(db_session).append_event(_event(2), _writer())
    db_session.rollback()
    assert db_session.query(AuditRecordEntity).count() == 1
    assert db_session.query(AuditRecordEntity).one().record_hash == first.record_hash


def test_append_failure_does_not_advance_ledger_state(db_session, monkeypatch):
    from app.storage import repository as repository_module
    first = AuditLedgerRepository(db_session).append_event(_event(1), _writer())
    state_before = db_session.query(LedgerStateEntity).one()
    before = (state_before.next_sequence, state_before.tip_hash)
    db_session.rollback()

    monkeypatch.setattr(repository_module, "sign_record_hash", lambda _hash: (_ for _ in ()).throw(RuntimeError("signing failure")))
    with pytest.raises(RuntimeError, match="signing failure"):
        AuditLedgerRepository(db_session).append_event(_event(2), _writer())
    assert not db_session.info.get("ledger_lock_acquired")
    db_session.rollback()
    state_after = db_session.query(LedgerStateEntity).one()
    assert (state_after.next_sequence, state_after.tip_hash) == before
    assert db_session.query(AuditRecordEntity).count() == 1
    assert db_session.query(AuditRecordEntity).one().record_hash == first.record_hash


@pytest.mark.parametrize("failure_method", ["flush", "commit"])
def test_append_persistence_failure_cleans_allocator_ownership(db_session, monkeypatch, failure_method):
    AuditLedgerRepository(db_session).append_event(_event(1), _writer())
    db_session.rollback()
    original = getattr(db_session, failure_method)

    def fail(*args, **kwargs):
        raise RuntimeError(f"append {failure_method} failure")

    monkeypatch.setattr(db_session, failure_method, fail)
    with pytest.raises(RuntimeError, match=f"append {failure_method} failure"):
        AuditLedgerRepository(db_session).append_event(_event(2), _writer())
    assert not db_session.info.get("ledger_lock_acquired")
    assert not db_session.info.get("ledger_transaction_invalid")
    monkeypatch.setattr(db_session, failure_method, original)
    db_session.rollback()
    assert db_session.query(AuditRecordEntity).count() == 1
    db_session.rollback()


def test_append_rollback_failure_invalidates_session(db_session, monkeypatch):
    AuditLedgerRepository(db_session).append_event(_event(1), _writer())
    db_session.rollback()

    monkeypatch.setattr(db_session, "commit", lambda: (_ for _ in ()).throw(RuntimeError("append commit failure")))
    monkeypatch.setattr(db_session, "rollback", lambda: (_ for _ in ()).throw(RuntimeError("append rollback failure")))
    with pytest.raises(RuntimeError, match="append commit failure"):
        AuditLedgerRepository(db_session).append_event(_event(2), _writer())
    assert not db_session.info.get("ledger_lock_acquired")
    assert db_session.info.get("ledger_transaction_invalid") is True
    with pytest.raises(RuntimeError, match="session was invalidated"):
        AuditLedgerRepository(db_session).append_event(_event(3), _writer())

"""Regression tests for integrity boundaries not covered by the happy paths."""

from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.schemas import AuditEventCreate, ViolationType
from app.storage.database import AuditRecordEntity, Base
from app.storage.repository import AuditLedgerRepository


def test_redacted_record_mutation_is_detected(client, db_session):
    created = client.post(
        "/audit/events",
        json={
            "eventType": "CLIENT_CREATED", "actorId": "advisor-7",
            "resourceType": "CLIENT", "resourceId": "client-7",
            "payload": {"name": "Ava", "ssn": "123-45-6789"},
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
            "payload": {}, "timestamp": "2026-10-07T12:00:00+05:30",
        },
    )
    assert response.status_code == 201
    assert response.json()["timestamp"] == "2026-10-07T06:30:00Z"
    server_timestamp = client.post(
        "/audit/events",
        json={"eventType": "LOGIN", "actorId": "user", "resourceType": "SESSION", "resourceId": "2", "payload": {}},
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
                resourceId=str(index), payload={}, timestamp="2026-10-07T00:00:00Z",
            )).sequence_num
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=8) as executor:
        sequence_numbers = list(executor.map(append, range(24)))

    assert sorted(sequence_numbers) == list(range(1, 25))

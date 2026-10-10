"""
Tests for Scenario A — Core Audit Log Service.
"""

from app.crypto.hasher import GENESIS_PREV_HASH
from app.models.schemas import ViolationType
from app.storage.database import AuditRecordEntity


def test_write_and_chain_linkage(client):
    # Write event 1 (Genesis block)
    resp1 = client.post(
        "/audit/events",
        json={
            "eventType": "USER_LOGIN",
            "actorId": "user-101",
            "resourceType": "SESSION",
            "resourceId": "sess-abc",
            "payload": {"ip": "192.168.1.1", "device": "MacBook"},
            "delegationReason": "scenario fixture ingestion",
            "timestamp": "2026-10-07T10:00:00Z",
        },
    )
    assert resp1.status_code == 201
    data1 = resp1.json()
    assert data1["sequenceNum"] == 1
    assert data1["prevHash"] == GENESIS_PREV_HASH
    assert len(data1["recordHash"]) == 64

    # Write event 2
    resp2 = client.post(
        "/audit/events",
        json={
            "eventType": "RECORD_UPDATED",
            "actorId": "user-101",
            "resourceType": "ACCOUNT",
            "resourceId": "acc-999",
            "payload": {"action": "email_change", "new_email": "alice@schwab.com"},
            "delegationReason": "scenario fixture ingestion",
            "timestamp": "2026-10-07T10:05:00Z",
        },
    )
    assert resp2.status_code == 201
    data2 = resp2.json()
    assert data2["sequenceNum"] == 2
    assert data2["prevHash"] == data1["recordHash"]

    # Verify chain
    verify_resp = client.get("/audit/verify")
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["intact"] is True
    assert v_data["recordsVerified"] == 2
    assert v_data["violationType"] == ViolationType.NONE.value


def test_query_filtering(client):
    events = [
        {"eventType": "LOGIN", "actorId": "alice", "resourceType": "AUTH", "resourceId": "1", "delegationReason": "scenario fixture ingestion", "timestamp": "2026-10-07T10:00:00Z"},
        {"eventType": "TRADE", "actorId": "alice", "resourceType": "ORDER", "resourceId": "100", "delegationReason": "scenario fixture ingestion", "timestamp": "2026-10-07T10:10:00Z"},
        {"eventType": "LOGIN", "actorId": "bob", "resourceType": "AUTH", "resourceId": "2", "delegationReason": "scenario fixture ingestion", "timestamp": "2026-10-07T10:15:00Z"},
        {"eventType": "TRANSFER", "actorId": "bob", "resourceType": "ACCOUNT", "resourceId": "200", "delegationReason": "scenario fixture ingestion", "timestamp": "2026-10-07T10:20:00Z"},
    ]
    for e in events:
        client.post("/audit/events", json=e)

    # Filter by actorId
    resp_actor = client.get("/audit/events?actorId=alice")
    assert resp_actor.status_code == 200
    assert resp_actor.json()["total"] == 2

    # Filter by eventType
    resp_type = client.get("/audit/events?eventType=LOGIN")
    assert resp_type.status_code == 200
    assert resp_type.json()["total"] == 2

    # Filter by resourceType and resourceId
    resp_res = client.get("/audit/events?resourceType=ORDER&resourceId=100")
    assert resp_res.status_code == 200
    assert resp_res.json()["total"] == 1

    # Filter by time range
    resp_time = client.get("/audit/events?fromTime=2026-10-07T10:05:00Z&toTime=2026-10-07T10:18:00Z")
    assert resp_time.status_code == 200
    assert resp_time.json()["total"] == 2


def test_tamper_detection_direct_content_mutation(client, db_session):
    """
    Directly modifies SQLite payload column to simulate malicious storage tampering.
    GET /audit/verify must detect CONTENT_HASH_MISMATCH.
    """
    client.post("/audit/events", json={"eventType": "TRANSFER", "actorId": "eve", "resourceType": "ACCOUNT", "resourceId": "9", "payload": {"amount": 500}, "delegationReason": "scenario fixture ingestion", "timestamp": "2026-10-07T10:00:00Z"})
    client.post("/audit/events", json={"eventType": "TRANSFER", "actorId": "eve", "resourceType": "ACCOUNT", "resourceId": "9", "payload": {"amount": 1000}, "delegationReason": "scenario fixture ingestion", "timestamp": "2026-10-07T10:01:00Z"})

    # Intact initially
    assert client.get("/audit/verify").json()["intact"] is True

    # Mutate record 1 payload directly in SQLite
    rec1 = db_session.query(AuditRecordEntity).filter_by(sequence_num=1).first()
    rec1.payload_json = '{"amount":999999}'
    db_session.commit()

    # Verify detection
    verify_resp = client.get("/audit/verify")
    assert verify_resp.status_code == 200
    result = verify_resp.json()
    assert result["intact"] is False
    assert result["firstBrokenSequence"] == 1
    assert result["violationType"] == ViolationType.CONTENT_HASH_MISMATCH.value


def test_tamper_detection_record_deletion(client, db_session):
    """
    Directly deletes a record in SQLite to simulate malicious truncation/deletion.
    """
    client.post("/audit/events", json={"eventType": "EVENT_A", "actorId": "u1", "resourceType": "R", "resourceId": "1", "delegationReason": "scenario fixture ingestion", "timestamp": "2026-10-07T10:00:00Z"})
    client.post("/audit/events", json={"eventType": "EVENT_B", "actorId": "u1", "resourceType": "R", "resourceId": "1", "delegationReason": "scenario fixture ingestion", "timestamp": "2026-10-07T10:01:00Z"})
    client.post("/audit/events", json={"eventType": "EVENT_C", "actorId": "u1", "resourceType": "R", "resourceId": "1", "delegationReason": "scenario fixture ingestion", "timestamp": "2026-10-07T10:02:00Z"})

    rec2 = db_session.query(AuditRecordEntity).filter_by(sequence_num=2).first()
    db_session.delete(rec2)
    db_session.commit()

    verify_resp = client.get("/audit/verify")
    result = verify_resp.json()
    assert result["intact"] is False
    assert result["violationType"] in [ViolationType.SEQUENCE_DISCONTINUITY.value, ViolationType.CHAIN_LINK_BROKEN.value]

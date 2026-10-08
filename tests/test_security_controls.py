"""End-to-end tests for authentication, signatures, export, and lifecycle integrity."""

from fastapi.testclient import TestClient

from app.crypto.signer import verify_record_signature
from app.crypto.hasher import compute_event_content_hash, compute_record_chain_hash
from app.main import app
from app.models.schemas import ViolationType
from app.security import _credentials
from app.storage.database import AuditRecordEntity


def _event():
    return {
        "eventType": "ACCOUNT_VIEWED", "actorId": "advisor", "resourceType": "ACCOUNT",
        "resourceId": "a-1", "payload": {"purpose": "review"},
        "timestamp": "2026-10-08T00:00:00Z",
    }


def test_api_key_is_required():
    with TestClient(app) as anonymous:
        response = anonymous.get("/audit/verify")
    assert response.status_code == 401


def test_role_is_enforced(monkeypatch):
    monkeypatch.setenv(
        "AUDIT_API_KEYS", '{"reader-key":{"subject":"reader","roles":["reader"]}}'
    )
    _credentials.cache_clear()
    try:
        with TestClient(app, headers={"X-API-Key": "reader-key"}) as read_only:
            assert read_only.get("/audit/events").status_code == 200
            assert read_only.post("/audit/events", json=_event()).status_code == 403
    finally:
        _credentials.cache_clear()


def test_signed_records_and_export_verify_offline(client):
    assert client.post("/audit/events", json=_event()).status_code == 201
    record = client.get("/audit/events").json()["items"][0]
    assert record["recordSignature"]

    bundle = client.get("/audit/export?actorId=advisor").json()
    assert record["signingKeyId"] in bundle["signingPublicKeys"]
    assert verify_record_signature(
        record["recordHash"], record["recordSignature"], bundle["signingPublicKeys"][record["signingKeyId"]]
    )


def test_export_includes_lifecycle_witnesses(client):
    event = dict(_event(), payload={"ssn": "123-45-6789"})
    assert client.post("/audit/events", json=event).status_code == 201
    assert client.post("/audit/redact", json={"sequenceNum": 1, "fieldPaths": ["ssn"], "reason": "privacy"}).status_code == 200
    bundle = client.get("/audit/export?actorId=advisor").json()
    assert len(bundle["integrityManifests"]) == 1
    assert bundle["integrityManifests"][0]["eventType"] == "AUDIT_RECORD_REDACTED"


def test_recomputed_forged_hash_is_rejected_by_signature(client, db_session):
    assert client.post("/audit/events", json=_event()).status_code == 201
    record = db_session.query(AuditRecordEntity).one()
    # An attacker who rewrites the hash chain but lacks the signing key cannot
    # make the old signature validate for their replacement hash.
    record.payload_json = '{"purpose":"forged"}'
    record.content_hash = compute_event_content_hash(
        record.event_type, record.actor_id, record.resource_type, record.resource_id,
        {"purpose": "forged"}, record.timestamp,
    )
    record.record_hash = compute_record_chain_hash(record.sequence_num, record.content_hash, record.prev_hash)
    db_session.commit()
    result = client.get("/audit/verify").json()
    assert result["intact"] is False
    assert result["violationType"] == ViolationType.SIGNATURE_MISMATCH.value


def test_archival_state_tampering_is_detected(client, db_session):
    old = dict(_event(), timestamp="2020-01-01T00:00:00Z")
    assert client.post("/audit/events", json=old).status_code == 201
    assert client.post("/audit/retention/apply", json={"retentionDays": 30, "reason": "policy"}).status_code == 200
    record = db_session.query(AuditRecordEntity).filter_by(sequence_num=1).one()
    record.archival_reason = "changed without journal"
    db_session.commit()
    result = client.get("/audit/verify").json()
    assert result["intact"] is False
    assert result["violationType"] == ViolationType.UNAUTHORIZED_ARCHIVAL.value

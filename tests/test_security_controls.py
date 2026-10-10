"""End-to-end tests for authentication, signatures, export, and lifecycle integrity."""

import pytest
from fastapi.testclient import TestClient

from app.crypto.signer import _private_key, public_key_b64, public_key_ring, verify_record_signature
from app.crypto.hasher import compute_event_content_hash, compute_record_chain_hash
from app.authorization import clear_authorization_caches, resource_registry
from app.main import app
from app.models.schemas import ViolationType
from app.security import _credentials
from app.security import authenticated_principal
from app.storage.database import AuditRecordEntity, LedgerStateEntity


def _event():
    return {
        "eventType": "ACCOUNT_VIEWED", "actorId": "advisor", "resourceType": "ACCOUNT",
        "resourceId": "a-1", "payload": {"purpose": "review"},
        "delegationReason": "scenario fixture ingestion",
        "timestamp": "2026-10-08T00:00:00Z",
    }


def test_api_key_is_required():
    with TestClient(app) as anonymous:
        response = anonymous.get("/audit/verify")
    assert response.status_code == 401


def test_malformed_api_key_configuration_fails_closed(monkeypatch):
    monkeypatch.setenv("AUDIT_API_KEYS", "not-json")
    _credentials.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="AUDIT_API_KEYS must be JSON"):
            authenticated_principal("any-key")
    finally:
        _credentials.cache_clear()


def test_malformed_resource_registry_fails_closed(monkeypatch):
    monkeypatch.setenv("AUDIT_RESOURCE_OWNERSHIP", "not-json")
    clear_authorization_caches()
    try:
        with pytest.raises(RuntimeError, match="AUDIT_RESOURCE_OWNERSHIP must be JSON"):
            resource_registry()
    finally:
        clear_authorization_caches()


def test_development_signing_key_survives_cache_reset(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_ENV", "development")
    monkeypatch.delenv("AUDIT_SIGNING_PRIVATE_KEY", raising=False)
    monkeypatch.setenv("AUDIT_DEVELOPMENT_KEY_PATH", str(tmp_path / "development.key"))
    _private_key.cache_clear()
    public_key_ring.cache_clear()
    first_public_key = public_key_b64()
    _private_key.cache_clear()
    public_key_ring.cache_clear()
    assert public_key_b64() == first_public_key
    _private_key.cache_clear()
    public_key_ring.cache_clear()


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


def test_writer_cannot_impersonate_another_actor(monkeypatch):
    monkeypatch.setenv(
        "AUDIT_API_KEYS", '{"writer-key":{"subject":"advisor-1","roles":["writer"],"legacyAccess":true}}'
    )
    _credentials.cache_clear()
    try:
        with TestClient(app, headers={"X-API-Key": "writer-key"}) as writer:
            assert writer.post("/audit/events", json=dict(_event(), actorId="other-user")).status_code == 403
            assert writer.post("/audit/events", json=dict(_event(), actorId="advisor-1")).status_code == 201
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


def test_ledger_state_tip_tampering_is_rejected(client, db_session):
    assert client.post("/audit/events", json=_event()).status_code == 201
    state = db_session.query(LedgerStateEntity).filter_by(singleton_id=1).one()
    state.tip_hash = "f" * 64
    db_session.commit()

    result = client.get("/audit/verify")

    assert result.status_code == 200
    assert result.json()["intact"] is False
    assert result.json()["violationType"] == ViolationType.RECORD_HASH_MISMATCH.value
    assert "ledger state" in result.json()["details"].lower()


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


def test_compliance_excludes_non_access_events_and_rejects_bad_times(client):
    access_event = dict(_event(), resourceType="CLIENT_ACCOUNT", eventType="ACCOUNT_VIEWED")
    unrelated_event = dict(access_event, eventType="UNRELATED_EVENT")
    assert client.post("/audit/events", json=access_event).status_code == 201
    assert client.post("/audit/events", json=unrelated_event).status_code == 201
    report = client.get("/audit/compliance/client-access?clientId=a-1").json()
    assert report["totalAccessEvents"] == 1
    assert client.get(
        "/audit/compliance/client-access?clientId=a-1&fromTime=2026-10-09T00:00:00Z&toTime=2026-10-08T00:00:00Z"
    ).status_code == 422


def test_end_to_end_ideal_workflow(client):
    events = [
        {"eventType": "ACCOUNT_VIEWED", "actorId": "advisor-lena", "resourceType": "CLIENT_ACCOUNT", "resourceId": "client-demo", "payload": {"justification": "PORTFOLIO_REVIEW", "clientConsent": True, "ssn": "123-45-6789"}, "delegationReason": "scenario fixture ingestion", "timestamp": "2026-10-01T09:00:00Z"},
        {"eventType": "HOLDINGS_EXPORTED", "actorId": "advisor-lena", "resourceType": "CLIENT_ACCOUNT", "resourceId": "client-demo", "payload": {"justification": "TAX_FILING_PREP", "exportFormat": "PDF"}, "delegationReason": "scenario fixture ingestion", "timestamp": "2026-10-01T09:30:00Z"},
        {"eventType": "ACCOUNT_VIEWED", "actorId": "intern-sam", "resourceType": "CLIENT_ACCOUNT", "resourceId": "client-demo", "payload": {"viewedFields": ["taxId"]}, "delegationReason": "scenario fixture ingestion", "timestamp": "2026-10-01T10:00:00Z"},
        {"eventType": "LOGIN", "actorId": "retention-service", "resourceType": "SYSTEM", "resourceId": "old-record", "payload": {}, "delegationReason": "scenario fixture ingestion", "timestamp": "2020-01-01T00:00:00Z"},
    ]
    for event in events:
        assert client.post("/audit/events", json=event).status_code == 201

    assert client.post("/audit/redact", json={"sequenceNum": 1, "fieldPaths": ["ssn"], "reason": "Approved privacy request"}).status_code == 200
    assert client.post("/audit/retention/apply", json={"retentionDays": 365, "reason": "Approved retention policy"}).status_code == 200

    verification = client.get("/audit/verify").json()
    assert verification["intact"] is True
    assert verification["recordsVerified"] == 6

    report = client.get("/audit/compliance/client-access?clientId=client-demo").json()
    assert report["totalAccessEvents"] == 3
    assert report["complianceStatus"] == "FLAGGED_FOR_REVIEW"
    assert any("intern-sam" in issue for issue in report["anomaliesDetected"])

    exported = client.get("/audit/export?resourceId=client-demo").json()
    assert exported["totalRecords"] == 3
    assert len(exported["integrityManifests"]) == 1

"""
Tests for Scenario B — Retention, Structured Redaction, and Verifiable Export.
"""

from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crypto.hasher import canonical_json, compute_sha256
from app.main import app
from app.routers.audit import get_db
from app.storage.database import AuditRecordEntity, Base

TEST_DATABASE_URL = "sqlite:///./test_scenario_b.db"
test_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


def test_retention_policy_archival_and_chain_intact():
    """
    Ensures that records older than retention threshold are marked as archived,
    and GET /audit/verify continues to confirm the hash chain is fully intact
    without false-positive alerts.
    """
    old_time = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    recent_time = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()

    # Create old event
    client.post(
        "/audit/events",
        json={
            "eventType": "LOGIN",
            "actorId": "user-old",
            "resourceType": "AUTH",
            "resourceId": "sess-1",
            "payload": {"ip": "10.0.0.1"},
            "timestamp": old_time,
        },
    )
    # Create recent event
    client.post(
        "/audit/events",
        json={
            "eventType": "TRADE",
            "actorId": "user-old",
            "resourceType": "ORDER",
            "resourceId": "ord-2",
            "payload": {"symbol": "SCHW", "qty": 50},
            "timestamp": recent_time,
        },
    )

    # Apply 30-day retention policy
    retention_resp = client.post(
        "/audit/retention/apply",
        json={"retentionDays": 30, "reason": "90-day SEC rule compliance archival"},
    )
    assert retention_resp.status_code == 200
    r_data = retention_resp.json()
    assert r_data["recordsArchived"] == 1
    assert r_data["archivedSequenceNumbers"] == [1]

    # Verify chain: MUST remain intact
    verify_resp = client.get("/audit/verify")
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["intact"] is True
    assert v_data["recordsVerified"] == 2


def test_structured_redaction_preserves_chain():
    """
    Tests that redacting sensitive fields (e.g. ssn, account_number):
    1. Masks the payload values in storage.
    2. Stores cryptographic commitment tokens.
    3. Preserves the chain hash so GET /audit/verify reports intact = true.
    """
    # Create event with sensitive PII
    post_resp = client.post(
        "/audit/events",
        json={
            "eventType": "CLIENT_ONBOARDING",
            "actorId": "advisor-1",
            "resourceType": "CLIENT_PROFILE",
            "resourceId": "client-999",
            "payload": {
                "name": "Jane Doe",
                "ssn": "123-45-6789",
                "bankAccount": "9876543210",
                "riskTolerance": "Moderate",
            },
            "timestamp": "2026-10-07T12:00:00Z",
        },
    )
    assert post_resp.status_code == 201
    orig_record_hash = post_resp.json()["recordHash"]
    orig_content_hash = post_resp.json()["contentHash"]

    # Redact SSN and bankAccount
    redact_resp = client.post(
        "/audit/redact",
        json={
            "sequenceNum": 1,
            "fieldPaths": ["ssn", "bankAccount"],
            "reason": "GDPR / CCPA privacy masking request",
        },
    )
    assert redact_resp.status_code == 200
    r_data = redact_resp.json()
    assert r_data["contentHashPreserved"] == orig_content_hash
    assert r_data["recordHashPreserved"] == orig_record_hash

    # Query event to inspect payload
    query_resp = client.get("/audit/events?resourceId=client-999")
    item = query_resp.json()["items"][0]
    payload = item["payload"]
    assert "[REDACTED:COMMITMENT:" in payload["ssn"]
    assert "[REDACTED:COMMITMENT:" in payload["bankAccount"]
    assert payload["name"] == "Jane Doe"  # Unredacted field preserved
    assert item["redactionMetadata"] is not None
    assert "ssn" in item["redactionMetadata"]["commitments"]

    # Chain verification MUST succeed
    verify_resp = client.get("/audit/verify")
    assert verify_resp.status_code == 200
    assert verify_resp.json()["intact"] is True


def test_verifiable_export_bundle():
    """
    Validates generation and independent verification of verifiable export bundles.
    """
    # Insert events for actor "compliance-user"
    for i in range(3):
        client.post(
            "/audit/events",
            json={
                "eventType": f"OPERATION_{i}",
                "actorId": "compliance-user",
                "resourceType": "PORTFOLIO",
                "resourceId": f"port-{i}",
                "payload": {"index": i},
                "timestamp": f"2026-10-07T10:0{i}:00Z",
            },
        )

    # Export for compliance-user
    export_resp = client.get("/audit/export?actorId=compliance-user")
    assert export_resp.status_code == 200
    bundle = export_resp.json()
    assert bundle["totalRecords"] == 3
    assert bundle["startSequenceNum"] == 1
    assert bundle["endSequenceNum"] == 3
    assert len(bundle["bundleIntegrityHash"]) == 64

    # Independent Verifier checks bundle integrity:
    record_hashes = [r["recordHash"] for r in bundle["records"]]
    recomputed_bundle_hash = compute_sha256(canonical_json(record_hashes))
    assert recomputed_bundle_hash == bundle["bundleIntegrityHash"]

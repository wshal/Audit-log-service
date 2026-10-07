"""
Tests for Scenario B — Retention, Structured Redaction, and Verifiable Export.
"""

from datetime import datetime, timedelta, timezone
from app.crypto.hasher import canonical_json, compute_sha256


def test_retention_policy_archival_and_chain_intact(client):
    old_time = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    recent_time = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()

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

    retention_resp = client.post(
        "/audit/retention/apply",
        json={"retentionDays": 30, "reason": "90-day SEC rule compliance archival"},
    )
    assert retention_resp.status_code == 200
    r_data = retention_resp.json()
    assert r_data["recordsArchived"] == 1
    assert r_data["archivedSequenceNumbers"] == [1]

    verify_resp = client.get("/audit/verify")
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["intact"] is True
    assert v_data["recordsVerified"] == 2


def test_structured_redaction_preserves_chain(client):
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

    query_resp = client.get("/audit/events?resourceId=client-999")
    item = query_resp.json()["items"][0]
    payload = item["payload"]
    assert "[REDACTED:COMMITMENT:" in payload["ssn"]
    assert "[REDACTED:COMMITMENT:" in payload["bankAccount"]
    assert payload["name"] == "Jane Doe"
    assert item["redactionMetadata"] is not None
    assert "ssn" in item["redactionMetadata"]["commitments"]

    verify_resp = client.get("/audit/verify")
    assert verify_resp.status_code == 200
    assert verify_resp.json()["intact"] is True


def test_verifiable_export_bundle(client):
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

    export_resp = client.get("/audit/export?actorId=compliance-user")
    assert export_resp.status_code == 200
    bundle = export_resp.json()
    assert bundle["totalRecords"] == 3
    assert bundle["startSequenceNum"] == 1
    assert bundle["endSequenceNum"] == 3
    assert len(bundle["bundleIntegrityHash"]) == 64

    record_hashes = [r["recordHash"] for r in bundle["records"]]
    recomputed_bundle_hash = compute_sha256(canonical_json(record_hashes))
    assert recomputed_bundle_hash == bundle["bundleIntegrityHash"]

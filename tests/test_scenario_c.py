"""
Tests for Scenario C — Compliance Reporting & Ambiguity Management.
"""


def test_compliance_client_access_report_generation(client):
    # 1. Valid access with regulatory justification
    client.post(
        "/audit/events",
        json={
            "eventType": "ACCOUNT_VIEWED",
            "actorId": "advisor-john",
            "resourceType": "CLIENT_ACCOUNT",
            "resourceId": "client-act-001",
                "payload": {
                "justification": "PORTFOLIO_REVIEW",
                "clientConsent": True,
                "viewedFields": ["balance", "holdings"],
                },
                "delegationReason": "scenario fixture ingestion",
            "timestamp": "2026-10-07T09:00:00Z",
        },
    )

    # 2. Another access by same advisor
    client.post(
        "/audit/events",
        json={
            "eventType": "HOLDINGS_EXPORTED",
            "actorId": "advisor-john",
            "resourceType": "CLIENT_ACCOUNT",
            "resourceId": "client-act-001",
                "payload": {
                "justification": "TAX_FILING_PREP",
                "exportFormat": "PDF",
                },
                "delegationReason": "scenario fixture ingestion",
            "timestamp": "2026-10-07T09:30:00Z",
        },
    )

    # 3. Suspicious access: missing justification
    client.post(
        "/audit/events",
        json={
            "eventType": "ACCOUNT_VIEWED",
            "actorId": "intern-sam",
            "resourceType": "CLIENT_ACCOUNT",
            "resourceId": "client-act-001",
                "payload": {
                "viewedFields": ["taxId", "ssn"],
                },
                "delegationReason": "scenario fixture ingestion",
            "timestamp": "2026-10-07T10:00:00Z",
        },
    )

    # Query Compliance Report for client-act-001
    resp = client.get("/audit/compliance/client-access?clientId=client-act-001")
    assert resp.status_code == 200
    report = resp.json()

    assert report["clientId"] == "client-act-001"
    assert report["totalAccessEvents"] == 3
    assert len(report["actorsInvolved"]) == 2
    assert report["chainIntegrityVerified"] is True

    # Check actor breakdown
    john_stats = next(a for a in report["actorsInvolved"] if a["actorId"] == "advisor-john")
    assert john_stats["accessCount"] == 2
    assert "PORTFOLIO_REVIEW" in john_stats["justifications"]
    assert "TAX_FILING_PREP" in john_stats["justifications"]

    # Check regulatory anomaly detection
    assert report["complianceStatus"] == "FLAGGED_FOR_REVIEW"
    assert any("intern-sam" in anomaly for anomaly in report["anomaliesDetected"])

"""P0 authorization tests: ordinary principals, two tenants, and object scope."""

import json
import pytest

from fastapi.testclient import TestClient

import app.main as main_module
from app.security import _credentials


def _configure_principals(monkeypatch):
    monkeypatch.setenv(
        "AUDIT_API_KEYS",
        json.dumps(
            {
                "writer-a": {
                    "credentialId": "cred-a",
                    "subject": "actor-a",
                    "roles": ["writer", "reader", "exporter", "privacy_officer", "retention_admin", "compliance_reviewer"],
                    "tenantGrants": [{"tenantId": "tenant-a", "actions": ["read", "write", "export", "redact", "retain", "compliance"], "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}] }],
                },
                "writer-b": {
                    "credentialId": "cred-b",
                    "subject": "actor-b",
                    "roles": ["writer", "reader", "exporter"],
                    "tenantGrants": [{"tenantId": "tenant-b", "actions": ["read", "write", "export"], "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-b"]}] }],
                },
                "global-auditor": {
                    "credentialId": "cred-global",
                    "subject": "global-auditor",
                    "roles": ["global_auditor"],
                    "tenantGrants": [],
                },
                "proxy-a": {
                    "credentialId": "cred-proxy-a",
                    "subject": "proxy-a",
                    "roles": ["writer", "audit_proxy"],
                    "tenantGrants": [{"tenantId": "tenant-a", "actions": ["write"], "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}] }],
                },
            }
        ),
    )
    monkeypatch.setenv("AUDIT_RESOURCE_OWNERSHIP", json.dumps({
        "CLIENT_ACCOUNT:client-a": {"tenantId": "tenant-a"},
        "CLIENT_ACCOUNT:client-b": {"tenantId": "tenant-b"},
    }))
    _credentials.cache_clear()
    from app.authorization import clear_authorization_caches
    clear_authorization_caches()


def _client(api_key):
    return TestClient(main_module.app, headers={"X-API-Key": api_key})


def _event(resource_id, actor_id, tenant_id):
    return {
        "tenantId": tenant_id,
        "eventType": "ACCOUNT_VIEWED",
        "actorId": actor_id,
        "resourceType": "CLIENT_ACCOUNT",
        "resourceId": resource_id,
        "payload": {"justification": "PORTFOLIO_REVIEW"},
        "timestamp": "2026-10-10T10:00:00Z",
    }


def test_two_tenant_resource_scope_and_direct_identifier_denial(client, monkeypatch):
    _configure_principals(monkeypatch)
    with _client("writer-a") as tenant_a, _client("writer-b") as tenant_b:
        assert tenant_a.post("/audit/events", json=_event("client-a", "actor-a", "tenant-a")).status_code == 201
        assert tenant_b.post("/audit/events", json=_event("client-b", "actor-b", "tenant-b")).status_code == 201

        own = tenant_a.get("/audit/events?tenantId=tenant-a&resourceId=client-a")
        foreign = tenant_a.get("/audit/events?tenantId=tenant-a&resourceId=client-b")
        assert own.status_code == 200
        assert own.json()["total"] == 1
        assert foreign.status_code in (403, 404)
        assert foreign.status_code != 200


def test_same_tenant_but_ungranted_resource_and_export_are_denied(client, monkeypatch):
    _configure_principals(monkeypatch)
    with _client("writer-a") as tenant_a:
        assert tenant_a.post("/audit/events", json=_event("client-a", "actor-a", "tenant-a")).status_code == 201
        assert tenant_a.get("/audit/events?tenantId=tenant-a&resourceId=client-other").status_code in (403, 404)
        assert tenant_a.get("/audit/export?tenantId=tenant-a&resourceId=client-other").status_code in (403, 404)


def test_ordinary_writer_cannot_impersonate_and_proxy_attribution_is_explicit(client, monkeypatch):
    _configure_principals(monkeypatch)
    with _client("writer-a") as ordinary, _client("proxy-a") as proxy:
        denied = ordinary.post("/audit/events", json=_event("client-a", "different-actor", "tenant-a"))
        assert denied.status_code == 403

        proxied = dict(_event("client-a", "different-actor", "tenant-a"), delegationReason="approved service action")
        response = proxy.post("/audit/events", json=proxied)
        assert response.status_code == 201
        body = response.json()
        assert body["actorId"] == "different-actor"
        assert body["authenticatedSubject"] == "proxy-a"
        assert body["attributionMode"] == "PROXY"


def test_global_verification_is_not_available_to_tenant_reader(client, monkeypatch):
    _configure_principals(monkeypatch)
    with _client("writer-a") as tenant_reader, _client("global-auditor") as global_auditor:
        assert tenant_reader.get("/audit/verify").status_code == 403
        assert global_auditor.get("/audit/verify").status_code == 200


def test_foreign_redaction_retention_and_compliance_do_not_mutate_or_leak(client, monkeypatch):
    _configure_principals(monkeypatch)
    with _client("writer-b") as tenant_b, _client("writer-a") as tenant_a:
        assert tenant_b.post("/audit/events", json=_event("client-b", "actor-b", "tenant-b")).status_code == 201
        assert tenant_a.post("/audit/redact", json={"tenantId": "tenant-a", "sequenceNum": 1, "fieldPaths": ["justification"], "reason": "privacy"}).status_code in (403, 404)
        assert tenant_a.post("/audit/retention/apply", json={"tenantId": "tenant-a", "retentionDays": 1, "reason": "policy"}).status_code in (403, 404)
        report = tenant_a.get("/audit/compliance/client-access?tenantId=tenant-a&clientId=client-b")
        assert report.status_code in (403, 404)


def test_v2_tenant_binding_and_transition_tampering_are_detected(client, db_session, monkeypatch):
    _configure_principals(monkeypatch)
    with _client("writer-a") as writer:
        assert writer.post("/audit/events", json=_event("client-a", "actor-a", "tenant-a")).status_code == 201
    from app.storage.database import AuditRecordEntity, AuditEpochTransitionEntity
    record = db_session.query(AuditRecordEntity).filter(AuditRecordEntity.protocol_version == 2).first()
    assert record is not None
    record.tenant_id = "tenant-b"
    db_session.commit()
    with _client("global-auditor") as auditor:
        result = auditor.get("/audit/verify")
    assert result.status_code == 503
    record.tenant_id = "tenant-a"
    record.authenticated_subject = "forged-caller"
    db_session.commit()
    with _client("global-auditor") as auditor:
        assert auditor.get("/audit/verify").status_code == 503
    record.authenticated_subject = "actor-a"
    record.tenant_id = "tenant-a"
    transition = db_session.query(AuditEpochTransitionEntity).first()
    transition.legacy_tip_hash = "f" * 64
    db_session.commit()
    with _client("global-auditor") as auditor:
        result = auditor.get("/audit/verify")
    assert result.status_code == 503


def test_unscoped_roles_cannot_read_or_mutate_legacy_or_tenant_data(client, monkeypatch):
    _configure_principals(monkeypatch)
    raw = json.loads(__import__("os").environ["AUDIT_API_KEYS"])
    raw["unscoped-admin"] = {"credentialId": "cred-admin", "subject": "admin", "roles": ["admin", "reader", "exporter", "privacy_officer", "retention_admin", "compliance_reviewer"]}
    monkeypatch.setenv("AUDIT_API_KEYS", json.dumps(raw)); _credentials.cache_clear()
    with _client("unscoped-admin") as admin:
        assert admin.get("/audit/events?resourceId=client-a").status_code == 403
        assert admin.get("/audit/export?resourceId=client-a").status_code == 403
        assert admin.post("/audit/retention/apply", json={"retentionDays": 1}).status_code == 403


def test_authorized_export_compliance_redaction_and_retention_are_scoped(client, monkeypatch):
    _configure_principals(monkeypatch)
    with _client("writer-a") as tenant_a:
        assert tenant_a.post("/audit/events", json=dict(_event("client-a", "actor-a", "tenant-a"), payload={"ssn": "secret", "justification": "PORTFOLIO_REVIEW"}, timestamp="2020-01-01T00:00:00Z")).status_code == 201
        export = tenant_a.get("/audit/export?resourceId=client-a")
        assert export.status_code == 200
        assert export.json()["totalRecords"] == 1
        compliance = tenant_a.get("/audit/compliance/client-access?clientId=client-a")
        assert compliance.status_code == 200
        assert "secret" not in compliance.text
        redaction = tenant_a.post("/audit/redact", json={"sequenceNum": 1, "fieldPaths": ["ssn"], "reason": "privacy"})
        assert redaction.status_code == 200
        retention = tenant_a.post("/audit/retention/apply", json={"tenantId": "tenant-a", "resourceId": "client-a", "retentionDays": 1, "reason": "policy"})
        assert retention.status_code == 200
        assert retention.json()["recordsArchived"] == 1
        with _client("global-auditor") as auditor:
            assert auditor.get("/audit/verify").json()["intact"] is True


def test_direct_repository_scope_is_required(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import QueryFilters
    from app.storage.repository import AuditLedgerRepository
    repo = AuditLedgerRepository(db_session)
    try:
        repo.query_events(QueryFilters(resourceId="client-a"), principal=None)
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 403
    else:
        raise AssertionError("unscoped repository query was allowed")


def test_v2_append_rolls_back_when_transition_signing_fails(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.storage.repository import AuditLedgerRepository
    from app.storage.database import AuditRecordEntity, AuditEpochTransitionEntity
    from app.models.schemas import AuditEventCreate
    from app.security import Principal
    import app.storage.repository as repository_module
    monkeypatch.setattr(repository_module, "sign_record_hash", lambda value: (_ for _ in ()).throw(RuntimeError("signing failure")))
    repo = AuditLedgerRepository(db_session)
    try:
        repo.append_event(AuditEventCreate(**_event("client-a", "actor-a", "tenant-a")), Principal("actor-a", frozenset({"writer"}), "cred-a"))
    except RuntimeError:
        pass
    assert db_session.query(AuditRecordEntity).count() == 0
    assert db_session.query(AuditEpochTransitionEntity).count() == 0


def test_admin_without_legacy_write_cannot_append_v1_but_explicit_writer_can(client, monkeypatch):
    _configure_principals(monkeypatch)
    raw = json.loads(__import__("os").environ["AUDIT_API_KEYS"])
    raw["admin-no-legacy"] = {"credentialId": "admin", "subject": "admin", "roles": ["admin", "writer"]}
    raw["legacy-writer"] = {"credentialId": "legacy", "subject": "legacy", "roles": ["writer"], "legacyAccess": True}
    monkeypatch.setenv("AUDIT_API_KEYS", json.dumps(raw)); _credentials.cache_clear()
    event = {"eventType": "LEGACY", "actorId": "admin", "resourceType": "CLIENT", "resourceId": "legacy-1", "payload": {}, "timestamp": "2026-01-01T00:00:00Z"}
    with _client("admin-no-legacy") as admin, _client("legacy-writer") as writer:
        assert admin.post("/audit/events", json=event).status_code == 403
        event["actorId"] = "legacy"
        assert writer.post("/audit/events", json=event).status_code == 201


def test_direct_verification_and_full_ledger_reads_require_capability(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.storage.repository import AuditLedgerRepository
    from app.services.verifier import ChainVerificationService
    from app.security import Principal
    repo = AuditLedgerRepository(db_session)
    try:
        repo.get_all_ordered_by_sequence()
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 403
    else:
        raise AssertionError("unscoped full-ledger read was allowed")
    try:
        ChainVerificationService.verify_ledger(db_session)
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 403
    else:
        raise AssertionError("unscoped verification was allowed")
    auditor = Principal("auditor", frozenset({"global_auditor"}), "cred-global")
    assert ChainVerificationService.verify_ledger(db_session, principal=auditor).intact is True


def test_nested_pii_is_projected_from_objects_and_arrays(client, monkeypatch):
    _configure_principals(monkeypatch)
    with _client("writer-a") as tenant_a:
        event = dict(_event("client-a", "actor-a", "tenant-a"), payload={"profile": {"ssn": "nested-secret", "name": "Ada"}, "accounts": [{"accountNumber": "hidden", "balance": 10}]})
        assert tenant_a.post("/audit/events", json=event).status_code == 201
        response = tenant_a.get("/audit/export?resourceId=client-a")
        assert response.status_code == 200
        payload = response.json()["records"][0]["payload"]
        assert "ssn" not in payload["profile"]
        assert payload["profile"]["name"] == "Ada"
        assert "accountNumber" not in payload["accounts"][0]


@pytest.mark.parametrize("field,value", [
    ("tenant_id", "tenant-b"),
    ("authenticated_subject", "forged"),
    ("credential_id", "forged-credential"),
    ("attribution_mode", "FORGED"),
    ("delegation_reason", "forged-reason"),
    ("protocol_version", 9),
])
def test_each_v2_integrity_field_tampering_fails(field, value, db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.storage.database import AuditRecordEntity
    from app.storage.repository import AuditLedgerRepository
    from app.models.schemas import AuditEventCreate
    from app.security import Principal
    from app.services.verifier import ChainVerificationService
    event = AuditEventCreate(**_event("client-a", "actor-a", "tenant-a"))
    repo = AuditLedgerRepository(db_session)
    repo.append_event(event, Principal("actor-a", frozenset({"writer"}), "cred-a", (), False))
    record = db_session.query(AuditRecordEntity).filter(AuditRecordEntity.protocol_version == 2).first()
    setattr(record, field, value)
    db_session.commit()
    result = ChainVerificationService.verify_ledger(db_session, Principal("auditor", frozenset({"global_auditor"}), "cred-global"))
    assert result.intact is False

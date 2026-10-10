"""P0 authorization tests: ordinary principals, two tenants, and object scope."""

import json
import pytest
from fastapi import HTTPException

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
        repo.append_event(AuditEventCreate(**_event("client-a", "actor-a", "tenant-a")), Principal("actor-a", frozenset({"writer"}), "cred-a", ({"tenantId": "tenant-a", "actions": ["write"], "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},)))
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
    from app.storage.database import initialize_ledger_state
    initialize_ledger_state(db_session.bind)
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
    repo.append_event(event, Principal("actor-a", frozenset({"writer"}), "cred-a", ({"tenantId": "tenant-a", "actions": ["write"], "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},), False))
    record = db_session.query(AuditRecordEntity).filter(AuditRecordEntity.protocol_version == 2).first()
    setattr(record, field, value)
    db_session.commit()
    result = ChainVerificationService.verify_ledger(db_session, Principal("auditor", frozenset({"global_auditor"}), "cred-global"))
    assert result.intact is False


def test_direct_lifecycle_and_compliance_boundaries_enforce_scope(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate
    from app.security import Principal
    from app.storage.repository import AuditLedgerRepository
    from app.services.lifecycle import LifecycleAndExportService
    from app.services.compliance import ComplianceService

    owner = Principal("actor-a", frozenset({"writer", "reader", "exporter", "privacy_officer", "retention_admin", "compliance_reviewer"}), "cred-a", (
        {"tenantId": "tenant-a", "actions": ["read", "write", "export", "redact", "retain", "compliance"], "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},
    ))
    foreign = Principal("actor-b", frozenset({"reader", "exporter", "privacy_officer", "retention_admin", "compliance_reviewer"}), "cred-b", (
        {"tenantId": "tenant-b", "actions": ["read", "export", "redact", "retain", "compliance"], "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-b"]}]},
    ))
    record = AuditLedgerRepository(db_session).append_event(
        AuditEventCreate(**_event("client-a", "actor-a", "tenant-a")), owner
    )
    with pytest.raises(Exception):
        LifecycleAndExportService.generate_verifiable_export(db_session, resource_id="client-a", principal=foreign)
    with pytest.raises(Exception):
        LifecycleAndExportService.redact_record_fields(db_session, record.sequence_num, ["justification"], "no", principal=foreign)
    with pytest.raises(Exception):
        LifecycleAndExportService.apply_retention_policy(db_session, 1, "no", tenant_id="tenant-a", resource_id="client-a", principal=foreign)
    with pytest.raises(Exception):
        ComplianceService.generate_client_access_audit_report(db_session, "client-a", principal=foreign)


def test_direct_pii_export_requires_explicit_pii_permission(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate
    from app.security import Principal
    from app.storage.repository import AuditLedgerRepository
    from app.services.lifecycle import LifecycleAndExportService
    owner = Principal("actor-a", frozenset({"writer", "exporter"}), "cred-a", (
        {"tenantId": "tenant-a", "actions": ["write", "export"], "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},
    ))
    AuditLedgerRepository(db_session).append_event(
        AuditEventCreate(**dict(_event("client-a", "actor-a", "tenant-a"), payload={"ssn": "secret"})), owner
    )
    with pytest.raises(Exception):
        LifecycleAndExportService.generate_verifiable_export(db_session, resource_id="client-a", include_pii=True, principal=owner)


def test_repository_v1_append_requires_explicit_legacy_write(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate
    from app.security import Principal
    from app.storage.repository import AuditLedgerRepository
    event = AuditEventCreate(eventType="LEGACY", actorId="actor", resourceType="CLIENT", resourceId="legacy", payload={}, timestamp="2026-01-01T00:00:00Z")
    repo = AuditLedgerRepository(db_session)
    with pytest.raises(Exception):
        repo.append_event(event)
    admin = Principal("admin", frozenset({"admin", "writer"}), "admin")
    with pytest.raises(Exception):
        repo.append_event(event, admin)
    legacy_writer = Principal("actor", frozenset({"writer"}), "legacy", (), True)
    assert repo.append_event(event, legacy_writer).sequence_num == 1


def test_repository_rejects_forged_actor_without_proxy_and_preserves_database(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate
    from app.security import Principal
    from app.storage.database import AuditRecordEntity
    from app.storage.repository import AuditLedgerRepository
    owner = Principal("actor-a", frozenset({"writer"}), "cred-a", (
        {"tenantId": "tenant-a", "actions": ["write"],
         "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},
    ))
    event = AuditEventCreate(**_event("client-a", "actor-b", "tenant-a"))
    with pytest.raises(HTTPException) as exc:
        AuditLedgerRepository(db_session).append_event(event, owner)
    assert exc.value.status_code == 403
    assert db_session.query(AuditRecordEntity).count() == 0


def test_repository_accepts_authenticated_and_explicit_proxy_attribution(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate
    from app.security import Principal
    from app.storage.repository import AuditLedgerRepository
    direct = Principal("actor-a", frozenset({"writer"}), "cred-a", (
        {"tenantId": "tenant-a", "actions": ["write"],
         "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},
    ))
    proxy = Principal("proxy-a", frozenset({"writer", "audit_proxy"}), "cred-p", (
        {"tenantId": "tenant-a", "actions": ["write"],
         "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},
    ))
    repo = AuditLedgerRepository(db_session)
    direct_record = repo.append_event(AuditEventCreate(**_event("client-a", "actor-a", "tenant-a")), direct)
    proxy_event = AuditEventCreate(**dict(_event("client-a", "actor-b", "tenant-a"), delegationReason="approved"))
    proxy_record = repo.append_event(proxy_event, proxy)
    assert direct_record.attribution_mode == "DIRECT"
    assert proxy_record.attribution_mode == "PROXY"
    assert proxy_record.authenticated_subject == "proxy-a"


def test_legacy_read_operations_require_global_auditor_and_mutations_are_denied(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate, QueryFilters
    from app.security import Principal
    from app.storage.database import AuditRecordEntity
    from app.storage.repository import AuditLedgerRepository
    from app.services.compliance import ComplianceService
    from app.services.lifecycle import LifecycleAndExportService
    writer = Principal("legacy", frozenset({"writer"}), "legacy", (), True)
    repo = AuditLedgerRepository(db_session)
    record = repo.append_event(AuditEventCreate(eventType="LEGACY", actorId="legacy", resourceType="CLIENT", resourceId="legacy-1", payload={"ssn": "secret"}, timestamp="2026-01-01T00:00:00Z"), writer)
    restricted_reader = Principal("legacy-reader", frozenset({"reader", "exporter", "compliance_reviewer", "privacy_officer", "retention_admin"}), "reader", (), True)
    operations = (
        (lambda: repo.query_events(QueryFilters(resourceId="legacy-1"), principal=restricted_reader), HTTPException),
        (lambda: LifecycleAndExportService.generate_verifiable_export(db_session, resource_id="legacy-1", principal=restricted_reader), HTTPException),
        (lambda: ComplianceService.generate_client_access_audit_report(db_session, "legacy-1", principal=restricted_reader), HTTPException),
        (lambda: LifecycleAndExportService.redact_record_fields(db_session, record.sequence_num, ["ssn"], "no", principal=restricted_reader), ValueError),
        (lambda: LifecycleAndExportService.apply_retention_policy(db_session, 1, "no", principal=restricted_reader), HTTPException),
    )
    for operation, expected_type in operations:
        with pytest.raises(expected_type) as exc:
            operation()
        if isinstance(exc.value, HTTPException):
            assert exc.value.status_code == 403
    assert db_session.query(AuditRecordEntity).count() == 1
    auditor = Principal("auditor", frozenset({"global_auditor", "reader", "exporter", "compliance_reviewer"}), "auditor")
    rows, total = repo.query_events(QueryFilters(resourceId="legacy-1"), principal=auditor)
    assert total == 1 and len(rows) == 1


def test_admin_and_proxy_require_delegation_for_v1_actor_substitution(client, monkeypatch):
    _configure_principals(monkeypatch)
    raw = json.loads(__import__("os").environ["AUDIT_API_KEYS"])
    raw["admin-legacy"] = {"credentialId": "admin", "subject": "admin", "roles": ["admin", "writer"], "legacyAccess": True}
    raw["proxy-legacy"] = {"credentialId": "proxy", "subject": "proxy", "roles": ["writer", "audit_proxy"], "legacyAccess": True}
    monkeypatch.setenv("AUDIT_API_KEYS", json.dumps(raw)); _credentials.cache_clear()
    event = {"eventType": "LEGACY", "actorId": "forged", "resourceType": "CLIENT", "resourceId": "legacy-1", "payload": {}, "timestamp": "2026-01-01T00:00:00Z"}
    with _client("admin-legacy") as admin, _client("proxy-legacy") as proxy:
        assert admin.post("/audit/events", json=event).status_code == 403
        assert proxy.post("/audit/events", json=event).status_code == 403
        event["delegationReason"] = "approved"
        assert proxy.post("/audit/events", json=event).status_code == 201


def test_legacy_pii_requires_dedicated_capability_for_compliance_and_export(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate
    from app.models.compliance import ComplianceAuditReport
    from app.security import Principal
    from app.services.compliance import ComplianceService
    from app.services.lifecycle import LifecycleAndExportService
    from app.storage.database import AuditRecordEntity
    from app.storage.repository import AuditLedgerRepository

    writer = Principal("legacy", frozenset({"writer"}), "legacy-writer", (), True)
    record = AuditLedgerRepository(db_session).append_event(
        AuditEventCreate(
            eventType="ACCOUNT_VIEWED",
            actorId="legacy",
            resourceType="CLIENT_ACCOUNT",
            resourceId="legacy-client",
            payload={"justification": "review", "ssn": "legacy-secret"},
            timestamp="2026-01-01T00:00:00Z",
        ),
        writer,
    )
    before = (record.payload_json, record.content_hash, record.record_hash)

    restricted = Principal(
        "auditor", frozenset({"global_auditor", "exporter", "compliance_reviewer", "pii_reader"}),
        "auditor", (), False, False, False,
    )
    denied_calls = (
        lambda: ComplianceService.generate_client_access_audit_report(
            db_session, "legacy-client", include_pii=True, principal=restricted,
        ),
        lambda: LifecycleAndExportService.generate_verifiable_export(
            db_session, resource_id="legacy-client", include_pii=True, principal=restricted,
        ),
    )
    for call in denied_calls:
        with pytest.raises(HTTPException) as exc:
            call()
        assert exc.value.status_code == 403
        assert "legacy-secret" not in str(exc.value.detail)

    current = db_session.query(AuditRecordEntity).filter_by(sequence_num=record.sequence_num).one()
    assert (current.payload_json, current.content_hash, current.record_hash) == before

    authorized = Principal(
        "auditor", frozenset({"global_auditor", "compliance_reviewer", "pii_reader"}),
        "authorized-auditor", (), False, False, True,
    )
    report = ComplianceService.generate_client_access_audit_report(
        db_session, "legacy-client", include_pii=True, principal=authorized,
    )
    assert isinstance(report, ComplianceAuditReport)
    assert report.accessEvents[0]["payload"]["ssn"] == "legacy-secret"


def test_query_requires_reader_role_even_with_tenant_grant(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate, QueryFilters
    from app.security import Principal
    from app.storage.repository import AuditLedgerRepository
    owner = Principal("actor-a", frozenset({"writer"}), "cred-a", (
        {"tenantId": "tenant-a", "actions": ["write", "read"], "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},
    ))
    AuditLedgerRepository(db_session).append_event(AuditEventCreate(**_event("client-a", "actor-a", "tenant-a")), owner)
    with pytest.raises(Exception):
        AuditLedgerRepository(db_session).query_events(
            QueryFilters(resourceType="CLIENT_ACCOUNT", resourceId="client-a"), principal=owner
        )
    reader = Principal("reader", frozenset({"reader"}), "reader", (
        {"tenantId": "tenant-a", "actions": ["read"], "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},
    ))
    rows, total = AuditLedgerRepository(db_session).query_events(
        QueryFilters(resourceType="CLIENT_ACCOUNT", resourceId="client-a"), principal=reader
    )
    assert total == 1 and len(rows) == 1


def test_legacy_access_without_reader_role_cannot_query_v1(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate, QueryFilters
    from app.security import Principal
    from app.storage.repository import AuditLedgerRepository
    repo = AuditLedgerRepository(db_session)
    repo.append_event(AuditEventCreate(eventType="LEGACY", actorId="writer", resourceType="CLIENT", resourceId="legacy", payload={}, timestamp="2026-01-01T00:00:00Z"), Principal("writer", frozenset({"writer"}), "writer", (), True))
    with pytest.raises(Exception):
        repo.query_events(QueryFilters(resourceId="legacy"), principal=Principal("legacy", frozenset(), "legacy", (), True))


def test_redaction_denial_is_indistinguishable_and_preserves_rows_and_manifests(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate
    from app.security import Principal
    from app.storage.database import AuditRecordEntity
    from app.storage.repository import AuditLedgerRepository
    from app.services.lifecycle import LifecycleAndExportService
    owner = Principal("actor-a", frozenset({"writer", "privacy_officer"}), "cred-a", (
        {"tenantId": "tenant-a", "actions": ["write", "redact"], "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},
    ))
    foreign = Principal("actor-b", frozenset({"privacy_officer"}), "cred-b", (
        {"tenantId": "tenant-b", "actions": ["redact"], "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-b"]}]},
    ))
    record = AuditLedgerRepository(db_session).append_event(
        AuditEventCreate(**dict(_event("client-a", "actor-a", "tenant-a"), payload={"ssn": "secret"})), owner
    )
    record_sequence = record.sequence_num
    before = [(r.sequence_num, r.payload_json, r.redaction_metadata_json, r.event_type) for r in db_session.query(AuditRecordEntity).all()]
    db_session.rollback()
    errors = []
    for sequence in (record_sequence, 9999):
        try:
            LifecycleAndExportService.redact_record_fields(db_session, sequence, ["ssn"], "denied", principal=foreign)
        except Exception as exc:
            errors.append((type(exc), str(exc)))
    after = [(r.sequence_num, r.payload_json, r.redaction_metadata_json, r.event_type) for r in db_session.query(AuditRecordEntity).all()]
    assert errors == [(ValueError, "Audit record not found"), (ValueError, "Audit record not found")]
    assert after == before
    db_session.rollback()
    assert LifecycleAndExportService.redact_record_fields(db_session, record_sequence, ["ssn"], "approved", principal=owner).sequenceNum == record_sequence


def test_direct_denials_preserve_retention_and_export_state(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate
    from app.security import Principal
    from app.storage.database import AuditRecordEntity
    from app.storage.repository import AuditLedgerRepository
    from app.services.lifecycle import LifecycleAndExportService

    owner = Principal("actor-a", frozenset({"writer", "exporter", "retention_admin"}), "cred-a", (
        {"tenantId": "tenant-a", "actions": ["write", "export", "retain"],
         "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},
    ))
    foreign = Principal("actor-b", frozenset({"exporter", "retention_admin"}), "cred-b", (
        {"tenantId": "tenant-b", "actions": ["export", "retain"],
         "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-b"]}]},
    ))
    record = AuditLedgerRepository(db_session).append_event(
        AuditEventCreate(**dict(_event("client-a", "actor-a", "tenant-a"), timestamp="2020-01-01T00:00:00Z")), owner
    )
    before = [(r.sequence_num, r.payload_json, r.is_archived, r.archived_at, r.archival_reason)
              for r in db_session.query(AuditRecordEntity).order_by(AuditRecordEntity.sequence_num).all()]
    with pytest.raises(Exception):
        LifecycleAndExportService.apply_retention_policy(
            db_session, 1, "unauthorized", tenant_id="tenant-a", resource_id="client-a", principal=foreign
        )
    with pytest.raises(Exception):
        LifecycleAndExportService.generate_verifiable_export(
            db_session, resource_id="client-a", principal=foreign
        )
    after = [(r.sequence_num, r.payload_json, r.is_archived, r.archived_at, r.archival_reason)
             for r in db_session.query(AuditRecordEntity).order_by(AuditRecordEntity.sequence_num).all()]
    assert after == before


def test_export_lifecycle_manifests_are_database_scoped_by_tenant(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate
    from app.security import Principal
    from app.storage.repository import AuditLedgerRepository
    from app.services.lifecycle import LifecycleAndExportService

    owner_a = Principal("actor-a", frozenset({"writer", "exporter", "privacy_officer"}), "cred-a", (
        {"tenantId": "tenant-a", "actions": ["write", "export", "redact"],
         "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},
    ))
    owner_b = Principal("actor-b", frozenset({"writer", "exporter", "privacy_officer"}), "cred-b", (
        {"tenantId": "tenant-b", "actions": ["write", "export", "redact"],
         "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-b"]}]},
    ))
    repo = AuditLedgerRepository(db_session)
    record_a = repo.append_event(AuditEventCreate(**_event("client-a", "actor-a", "tenant-a")), owner_a)
    record_b = repo.append_event(AuditEventCreate(**_event("client-b", "actor-b", "tenant-b")), owner_b)
    record_a_sequence = record_a.sequence_num
    record_b_sequence = record_b.sequence_num
    db_session.rollback()
    LifecycleAndExportService.redact_record_fields(db_session, record_a_sequence, ["justification"], "a", owner_a)
    LifecycleAndExportService.redact_record_fields(db_session, record_b_sequence, ["justification"], "b", owner_b)

    bundle = LifecycleAndExportService.generate_verifiable_export(
        db_session, resource_id="client-a", principal=owner_a
    )
    assert bundle.totalRecords == 1
    assert {m["tenantId"] for m in bundle.integrityManifests} == {"tenant-a"}
    assert all(m["payload"].get("redactedSequenceNum") == record_a.sequence_num for m in bundle.integrityManifests)


def test_redaction_failure_rolls_back_and_clears_allocator_ownership(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate
    from app.security import Principal
    from app.storage.database import AuditRecordEntity, LedgerStateEntity
    from app.storage.repository import AuditLedgerRepository
    from app.services.lifecycle import LifecycleAndExportService

    owner = Principal("actor-a", frozenset({"writer", "privacy_officer"}), "cred-a", (
        {"tenantId": "tenant-a", "actions": ["write", "redact"],
         "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},
    ))
    record = AuditLedgerRepository(db_session).append_event(
        AuditEventCreate(**dict(_event("client-a", "actor-a", "tenant-a"), payload={"justification": "before"})), owner
    )
    record_sequence = record.sequence_num
    db_session.rollback()
    before = db_session.query(AuditRecordEntity).one().payload_json
    state_before = db_session.query(LedgerStateEntity).one()
    state_snapshot = (state_before.next_sequence, state_before.tip_hash)
    db_session.rollback()

    original_journal = LifecycleAndExportService._append_lifecycle_journal

    def fail_journal(*args, **kwargs):
        raise RuntimeError("journal signing failure")

    monkeypatch.setattr(LifecycleAndExportService, "_append_lifecycle_journal", fail_journal)
    with pytest.raises(RuntimeError, match="journal signing failure"):
        LifecycleAndExportService.redact_record_fields(db_session, record_sequence, ["justification"], "test", owner)
    assert not db_session.info.get("ledger_lock_acquired")
    assert not db_session.in_transaction()
    assert db_session.query(AuditRecordEntity).one().payload_json == before
    state_after = db_session.query(LedgerStateEntity).one()
    assert (state_after.next_sequence, state_after.tip_hash) == state_snapshot
    db_session.rollback()

    monkeypatch.setattr(LifecycleAndExportService, "_append_lifecycle_journal", staticmethod(original_journal))
    result = LifecycleAndExportService.redact_record_fields(
        db_session, record_sequence, ["justification"], "retry", owner
    )
    assert result.sequenceNum == record_sequence


def test_retention_failure_rolls_back_archive_and_allocator_state(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate
    from app.security import Principal
    from app.storage.database import AuditRecordEntity, LedgerStateEntity
    from app.storage.repository import AuditLedgerRepository
    from app.services.lifecycle import LifecycleAndExportService

    owner = Principal("actor-a", frozenset({"writer", "retention_admin"}), "cred-a", (
        {"tenantId": "tenant-a", "actions": ["write", "retain"],
         "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},
    ))
    record = AuditLedgerRepository(db_session).append_event(
        AuditEventCreate(**dict(_event("client-a", "actor-a", "tenant-a"), timestamp="2020-01-01T00:00:00Z")), owner
    )
    record_sequence = record.sequence_num
    db_session.rollback()
    before = db_session.query(AuditRecordEntity).one()
    before_state = (before.is_archived, before.archived_at, before.archival_reason)
    state = db_session.query(LedgerStateEntity).one()
    state_snapshot = (state.next_sequence, state.tip_hash)
    db_session.rollback()

    original_journal = LifecycleAndExportService._append_lifecycle_journal
    monkeypatch.setattr(
        LifecycleAndExportService,
        "_append_lifecycle_journal",
        staticmethod(lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("journal failure"))),
    )
    with pytest.raises(RuntimeError, match="journal failure"):
        LifecycleAndExportService.apply_retention_policy(db_session, 1, "test", tenant_id="tenant-a", resource_id="client-a", principal=owner)
    assert not db_session.info.get("ledger_lock_acquired")
    assert not db_session.in_transaction()
    after = db_session.query(AuditRecordEntity).one()
    assert (after.is_archived, after.archived_at, after.archival_reason) == before_state
    state_after = db_session.query(LedgerStateEntity).one()
    assert (state_after.next_sequence, state_after.tip_hash) == state_snapshot
    db_session.rollback()
    monkeypatch.setattr(LifecycleAndExportService, "_append_lifecycle_journal", staticmethod(original_journal))
    assert record_sequence == after.sequence_num


@pytest.mark.parametrize("failure_method", ["flush", "commit"])
def test_redaction_persistence_failure_cleans_allocator_ownership(db_session, monkeypatch, failure_method):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate
    from app.security import Principal
    from app.storage.database import AuditRecordEntity
    from app.storage.repository import AuditLedgerRepository
    from app.services.lifecycle import LifecycleAndExportService

    owner = Principal("actor-a", frozenset({"writer", "privacy_officer"}), "cred-a", (
        {"tenantId": "tenant-a", "actions": ["write", "redact"],
         "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},
    ))
    record = AuditLedgerRepository(db_session).append_event(
        AuditEventCreate(**dict(_event("client-a", "actor-a", "tenant-a"), payload={"justification": "before"})), owner
    )
    sequence = record.sequence_num
    db_session.rollback()
    before = db_session.query(AuditRecordEntity).one().payload_json
    db_session.rollback()
    original = getattr(db_session, failure_method)
    monkeypatch.setattr(db_session, failure_method, lambda *a, **k: (_ for _ in ()).throw(RuntimeError(f"redaction {failure_method} failure")))
    with pytest.raises(RuntimeError, match=f"redaction {failure_method} failure"):
        LifecycleAndExportService.redact_record_fields(db_session, sequence, ["justification"], "test", owner)
    assert not db_session.info.get("ledger_lock_acquired")
    assert not db_session.info.get("ledger_transaction_invalid")
    monkeypatch.setattr(db_session, failure_method, original)
    db_session.rollback()
    assert db_session.query(AuditRecordEntity).one().payload_json == before
    db_session.rollback()


def test_lifecycle_rollback_failure_invalidates_session(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate
    from app.security import Principal
    from app.storage.repository import AuditLedgerRepository
    from app.services.lifecycle import LifecycleAndExportService

    owner = Principal("actor-a", frozenset({"writer", "privacy_officer"}), "cred-a", (
        {"tenantId": "tenant-a", "actions": ["write", "redact"],
         "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},
    ))
    record = AuditLedgerRepository(db_session).append_event(
        AuditEventCreate(**dict(_event("client-a", "actor-a", "tenant-a"), payload={"justification": "before"})), owner
    )
    sequence = record.sequence_num
    db_session.rollback()
    original_journal = LifecycleAndExportService._append_lifecycle_journal
    monkeypatch.setattr(LifecycleAndExportService, "_append_lifecycle_journal", staticmethod(lambda *a, **k: (_ for _ in ()).throw(RuntimeError("journal failure"))))
    monkeypatch.setattr(db_session, "rollback", lambda: (_ for _ in ()).throw(RuntimeError("rollback failure")))
    with pytest.raises(RuntimeError, match="journal failure"):
        LifecycleAndExportService.redact_record_fields(db_session, sequence, ["justification"], "test", owner)
    assert not db_session.info.get("ledger_lock_acquired")
    assert db_session.info.get("ledger_transaction_invalid") is True
    monkeypatch.setattr(LifecycleAndExportService, "_append_lifecycle_journal", staticmethod(original_journal))
    with pytest.raises(RuntimeError, match="session was invalidated"):
        LifecycleAndExportService.redact_record_fields(db_session, sequence, ["justification"], "retry", owner)


def test_authenticated_actor_binding_cannot_be_replaced_by_request_actor(client, monkeypatch):
    _configure_principals(monkeypatch)
    with _client("writer-a") as writer:
        response = writer.post("/audit/events", json=_event("client-a", "actor-b", "tenant-a"))
    assert response.status_code == 403


def test_compliance_unknown_or_foreign_selector_and_pii_are_denied(db_session, monkeypatch):
    _configure_principals(monkeypatch)
    from app.models.schemas import AuditEventCreate
    from app.security import Principal
    from app.storage.repository import AuditLedgerRepository
    from app.services.compliance import ComplianceService

    writer = Principal("actor-a", frozenset({"writer"}), "cred-a", (
        {"tenantId": "tenant-a", "actions": ["write"],
         "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},
    ))
    reviewer = Principal("reviewer", frozenset({"compliance_reviewer"}), "cred-review", (
        {"tenantId": "tenant-a", "actions": ["compliance"],
         "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},
    ))
    AuditLedgerRepository(db_session).append_event(
        AuditEventCreate(**dict(_event("client-a", "actor-a", "tenant-a"), eventType="ACCOUNT_VIEWED",
                                payload={"justification": "review", "ssn": "secret"})), writer
    )
    with pytest.raises(Exception):
        ComplianceService.generate_client_access_audit_report(
            db_session, "client-b", principal=reviewer
        )
    with pytest.raises(Exception):
        ComplianceService.generate_client_access_audit_report(
            db_session, "client-a", include_pii=True, principal=reviewer
        )


def test_tenant_query_counts_and_pagination_do_not_disclose_foreign_rows(client, monkeypatch):
    _configure_principals(monkeypatch)
    with _client("writer-a") as tenant_a, _client("writer-b") as tenant_b:
        assert tenant_a.post("/audit/events", json=_event("client-a", "actor-a", "tenant-a")).status_code == 201
        assert tenant_b.post("/audit/events", json=_event("client-b", "actor-b", "tenant-b")).status_code == 201
        denied = tenant_a.get("/audit/events?resourceId=client-b&limit=1&offset=0")
        assert denied.status_code in (403, 404)
        assert "total" not in denied.json()

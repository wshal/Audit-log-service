"""Crash-safe keyed append tests for the audit-event endpoint."""

from app.rate_limit import limiter
import json
import pytest
from app.security import _credentials
from app.authorization import clear_authorization_caches
from app.storage.database import AuditRecordEntity, IdempotencyRecordEntity
from app.models.schemas import AuditEventCreate
from app.storage.repository import AuditLedgerRepository, IdempotencyCommitUnknown
from app.security import Principal
from app.crypto.hasher import canonical_json
import hashlib
from concurrent.futures import ThreadPoolExecutor
from app.credential_store import provision, revoke
from app.authorization import clear_authorization_caches


def _event(*, payload=None, timestamp="2026-01-01T00:00:00Z"):
    return {
        "eventType": "USER_LOGIN",
        "actorId": "local-development",
        "resourceType": "CLIENT",
        "resourceId": "client-1",
        "payload": payload or {"ok": True},
        "timestamp": timestamp,
    }


def test_first_keyed_append_and_replay_do_not_duplicate(client, db_session):
    limiter.clear()
    key = "idem-key-00000001"
    first = client.post("/audit/events", json=_event(), headers={"Idempotency-Key": key})
    replay = client.post("/audit/events", json=_event(), headers={"Idempotency-Key": key})
    assert first.status_code == 201
    assert replay.status_code == 200
    assert replay.headers["Idempotent-Replay"] == "true"
    assert replay.json()["sequenceNum"] == first.json()["sequenceNum"]
    assert db_session.query(AuditRecordEntity).count() == 1
    assert db_session.query(IdempotencyRecordEntity).count() == 1


def test_key_fingerprint_conflict_does_not_mutate_ledger(client, db_session):
    key = "idem-key-00000002"
    first = client.post("/audit/events", json=_event(), headers={"Idempotency-Key": key})
    before = db_session.query(AuditRecordEntity).count()
    conflict = client.post(
        "/audit/events", json=_event(payload={"ok": False}), headers={"Idempotency-Key": key}
    )
    assert first.status_code == 201
    assert conflict.status_code == 409
    assert db_session.query(AuditRecordEntity).count() == before


def test_key_contract_requires_valid_key_and_explicit_timestamp(client, db_session):
    missing_timestamp = _event()
    missing_timestamp.pop("timestamp")
    assert client.post(
        "/audit/events", json=missing_timestamp,
        headers={"Idempotency-Key": "idem-key-00000003"},
    ).status_code == 400
    assert client.post(
        "/audit/events", json=_event(), headers={"Idempotency-Key": "bad"}
    ).status_code == 400
    assert client.post(
        "/audit/events", json=_event(), headers={"Idempotency-Key": "x" * 129}
    ).status_code == 400
    assert db_session.query(IdempotencyRecordEntity).count() == 0


def test_same_key_isolated_by_authenticated_principal(client, db_session, monkeypatch):
    monkeypatch.setenv("AUDIT_API_KEYS", '{"first":{"subject":"first","roles":["writer"],"legacyWrite":true},"second":{"subject":"second","roles":["writer"],"legacyWrite":true}}')
    _credentials.cache_clear()
    key = "idem-key-00000004"
    body_a = _event()
    body_a["actorId"] = "first"
    body_b = _event()
    body_b["actorId"] = "second"
    first = client.post("/audit/events", json=body_a, headers={"X-API-Key": "first", "Idempotency-Key": key})
    second = client.post("/audit/events", json=body_b, headers={"X-API-Key": "second", "Idempotency-Key": key})
    assert first.status_code == 201
    assert second.status_code == 201
    assert db_session.query(AuditRecordEntity).count() == 2
    assert db_session.query(IdempotencyRecordEntity).count() == 2


def test_same_key_isolated_by_tenant_scope(client, db_session, monkeypatch):
    monkeypatch.setenv("AUDIT_RESOURCE_OWNERSHIP", '{"CLIENT_ACCOUNT:client-a":"tenant-a","CLIENT_ACCOUNT:client-b":"tenant-b"}')
    monkeypatch.setenv("AUDIT_API_KEYS", '{"tenant-a-key":{"subject":"actor-a","roles":["writer"],"tenantGrants":[{"tenantId":"tenant-a","actions":["write"],"resourceScopes":[{"resourceType":"CLIENT_ACCOUNT","resourceIds":["client-a"]}]}]},"tenant-b-key":{"subject":"actor-b","roles":["writer"],"tenantGrants":[{"tenantId":"tenant-b","actions":["write"],"resourceScopes":[{"resourceType":"CLIENT_ACCOUNT","resourceIds":["client-b"]}]}]}}')
    _credentials.cache_clear()
    clear_authorization_caches()
    key = "idem-key-00000008"
    body_a = {**_event(timestamp="2026-01-01T00:00:01Z"), "actorId": "actor-a", "resourceType": "CLIENT_ACCOUNT", "resourceId": "client-a", "tenantId": "tenant-a"}
    body_b = {**_event(timestamp="2026-01-01T00:00:01Z"), "actorId": "actor-b", "resourceType": "CLIENT_ACCOUNT", "resourceId": "client-b", "tenantId": "tenant-b"}
    first = client.post("/audit/events", json=body_a, headers={"X-API-Key": "tenant-a-key", "Idempotency-Key": key})
    second = client.post("/audit/events", json=body_b, headers={"X-API-Key": "tenant-b-key", "Idempotency-Key": key})
    assert first.status_code == 201
    assert second.status_code == 201
    assert db_session.query(AuditRecordEntity).count() == 2
    assert db_session.query(IdempotencyRecordEntity).count() == 2


def test_expired_key_can_be_reused_after_explicit_cleanup(client, db_session):
    from datetime import datetime, timedelta, timezone

    key = "idem-key-00000005"
    assert client.post("/audit/events", json=_event(), headers={"Idempotency-Key": key}).status_code == 201
    row = db_session.query(IdempotencyRecordEntity).one()
    row.expires_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    db_session.commit()
    assert AuditLedgerRepository.cleanup_expired_idempotency(db_session) == 1
    second = client.post("/audit/events", json=_event(), headers={"Idempotency-Key": key})
    assert second.status_code == 201
    assert db_session.query(AuditRecordEntity).count() == 2


def test_cleanup_rejects_caller_transaction_without_committing_pending_work(isolated_test_application, db_session):
    event = AuditEventCreate(**_event())
    principal = Principal("local-development", frozenset({"writer"}), "development", (), True, True)
    AuditLedgerRepository(db_session).append_event_idempotent(
        event, principal, scope_principal="development", scope_tenant="__legacy__",
        scope_method="POST", scope_endpoint="/audit/events", idempotency_key="idem-key-00000009",
        request_fingerprint="f" * 64,
    )
    pending = IdempotencyRecordEntity(
        scope_principal="pending", scope_tenant="__legacy__", scope_method="POST",
        scope_endpoint="/audit/events", idempotency_key="pending-key",
        request_fingerprint="p" * 64, audit_record_id=1,
        created_at="2026-01-01T00:00:00Z", expires_at="2026-01-01T00:00:01Z",
    )
    db_session.add(pending)
    with pytest.raises(RuntimeError, match="idle maintenance session"):
        AuditLedgerRepository.cleanup_expired_idempotency(db_session)
    assert pending in db_session.new
    db_session.rollback()
    assert db_session.query(IdempotencyRecordEntity).filter_by(scope_principal="pending").count() == 0


def test_credential_revocation_blocks_idempotent_replay(client, db_session, monkeypatch, tmp_path):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    monkeypatch.setenv("AUDIT_RESOURCE_OWNERSHIP", '{"CLIENT_ACCOUNT:client-a":"tenant-a"}')
    token = provision(
        "actor-a", ["writer"], credential_id="credential-a",
        tenant_grants=[{"tenantId": "tenant-a", "actions": ["write"], "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]}],
        expires_at="2099-01-01T00:00:00Z",
    )
    clear_authorization_caches()
    body = {**_event(timestamp="2026-01-01T00:00:10Z"), "actorId": "actor-a", "resourceType": "CLIENT_ACCOUNT", "resourceId": "client-a", "tenantId": "tenant-a"}
    key = "idem-key-00000010"
    first = client.post("/audit/events", json=body, headers={"X-API-Key": token, "Idempotency-Key": key})
    assert first.status_code == 201
    before = db_session.query(AuditRecordEntity).count()
    revoke("credential-a")
    replay = client.post("/audit/events", json=body, headers={"X-API-Key": token, "Idempotency-Key": key})
    assert replay.status_code == 401
    assert first.json()["recordHash"] not in replay.text
    assert db_session.query(AuditRecordEntity).count() == before


def test_v1_and_v2_scopes_do_not_collide(client, db_session, monkeypatch):
    monkeypatch.setenv("AUDIT_API_KEYS", json.dumps({"shared-key": {
        "subject": "shared-actor", "roles": ["writer"], "legacyWrite": True,
        "tenantGrants": [{"tenantId": "tenant-a", "actions": ["write"], "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}] }],
    }}))
    monkeypatch.setenv("AUDIT_RESOURCE_OWNERSHIP", '{"CLIENT_ACCOUNT:client-a":"tenant-a"}')
    _credentials.cache_clear()
    clear_authorization_caches()
    key = "idem-key-00000011"
    legacy = {**_event(timestamp="2026-01-01T00:00:11Z"), "actorId": "shared-actor"}
    v2 = {**_event(timestamp="2026-01-01T00:00:12Z"), "actorId": "shared-actor", "resourceType": "CLIENT_ACCOUNT", "resourceId": "client-a", "tenantId": "tenant-a"}
    first = client.post("/audit/events", json=legacy, headers={"X-API-Key": "shared-key", "Idempotency-Key": key})
    second = client.post("/audit/events", json=v2, headers={"X-API-Key": "shared-key", "Idempotency-Key": key})
    assert first.status_code == 201
    assert second.status_code == 201
    assert db_session.query(IdempotencyRecordEntity).count() == 2


def test_http_ambiguous_commit_returns_bounded_503(client, monkeypatch):
    from app.routers import audit as audit_router
    def uncertain(*args, **kwargs):
        raise IdempotencyCommitUnknown("internal marker")
    monkeypatch.setattr(audit_router.AuditLedgerRepository, "append_event_idempotent", uncertain)
    response = client.post("/audit/events", json=_event(), headers={"Idempotency-Key": "idem-key-00000012"})
    assert response.status_code == 503
    assert "retry with the same Idempotency-Key" in response.json()["detail"]
    assert "internal marker" not in response.text


def test_commit_outcome_unknown_is_replayed_by_later_lookup(isolated_test_application, monkeypatch):
    event = AuditEventCreate(**_event())
    principal = Principal("local-development", frozenset({"writer"}), "development", (), True, True)
    material = {
        "eventType": event.eventType, "actorId": event.actorId,
        "resourceType": event.resourceType, "resourceId": event.resourceId,
        "payload": event.payload, "timestamp": event.timestamp,
        "tenantId": event.tenantId, "impersonatedActorId": event.impersonatedActorId,
        "delegationReason": event.delegationReason,
    }
    fingerprint = hashlib.sha256(canonical_json(material).encode()).hexdigest()
    session = isolated_test_application["session_factory"]()
    original_commit = session.commit

    def commit_then_fail():
        original_commit()
        raise OSError("connection lost after commit")

    monkeypatch.setattr(session, "commit", commit_then_fail)
    with pytest.raises(IdempotencyCommitUnknown):
        AuditLedgerRepository(session).append_event_idempotent(
            event, principal, scope_principal="development", scope_tenant="__legacy__",
            scope_method="POST", scope_endpoint="/audit/events",
            idempotency_key="idem-key-00000006", request_fingerprint=fingerprint,
        )
    session.close()
    retry_session = isolated_test_application["session_factory"]()
    try:
        record, replayed = AuditLedgerRepository(retry_session).append_event_idempotent(
            event, principal, scope_principal="development", scope_tenant="__legacy__",
            scope_method="POST", scope_endpoint="/audit/events",
            idempotency_key="idem-key-00000006", request_fingerprint=fingerprint,
        )
        assert replayed is True
        assert record.sequence_num == 1
        assert retry_session.query(AuditRecordEntity).count() == 1
    finally:
        retry_session.close()


def test_concurrent_duplicate_sessions_append_once(isolated_test_application):
    event = AuditEventCreate(**_event())
    principal = Principal("local-development", frozenset({"writer"}), "development", (), True, True)
    material = {
        "eventType": event.eventType, "actorId": event.actorId,
        "resourceType": event.resourceType, "resourceId": event.resourceId,
        "payload": event.payload, "timestamp": event.timestamp,
        "tenantId": event.tenantId, "impersonatedActorId": event.impersonatedActorId,
        "delegationReason": event.delegationReason,
    }
    fingerprint = hashlib.sha256(canonical_json(material).encode()).hexdigest()

    def worker():
        session = isolated_test_application["session_factory"]()
        try:
            record, replayed = AuditLedgerRepository(session).append_event_idempotent(
                event, principal, scope_principal="development", scope_tenant="__legacy__",
                scope_method="POST", scope_endpoint="/audit/events",
                idempotency_key="idem-key-00000007", request_fingerprint=fingerprint,
            )
            return record.sequence_num, replayed
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: worker(), range(2)))
    assert sorted(results) == [(1, False), (1, True)]
    session = isolated_test_application["session_factory"]()
    try:
        assert session.query(AuditRecordEntity).count() == 1
        assert session.query(IdempotencyRecordEntity).count() == 1
    finally:
        session.close()

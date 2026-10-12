"""End-to-end tests for authentication, signatures, export, and lifecycle integrity."""

import pytest
import hashlib
import json
import multiprocessing
import os
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.crypto.signer import _private_key, public_key_b64, public_key_ring, verify_record_signature
from app.crypto.hasher import compute_event_content_hash, compute_record_chain_hash
from app.authorization import clear_authorization_caches, resource_registry
from app.main import app
from app.models.schemas import ViolationType
from app.security import _credentials
from app.security import authenticated_principal
from app.storage.database import AuditRecordEntity, LedgerStateEntity
from app.credential_store import acknowledge_delivery, activate, provision, revoke, rotate
from app.credential_store import CredentialAuthorityError, _operator_lock
from app.credential_store import load_manifest


def _manifest_auth_worker(path, token, result_queue):
    os.environ["AUDIT_CREDENTIAL_MANIFEST"] = path
    from app.credential_store import authenticate
    result_queue.put(authenticate(token) is not None)


def _provision_worker(path, worker_id, result_queue):
    os.environ["AUDIT_CREDENTIAL_MANIFEST"] = path
    from app.credential_store import provision
    try:
        provision(f"worker-{worker_id}", ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id=f"worker-{worker_id}")
        result_queue.put((worker_id, "ok"))
    except BaseException as exc:
        result_queue.put((worker_id, type(exc).__name__))


def _rotate_or_revoke_worker(path, operation, result_queue):
    os.environ["AUDIT_CREDENTIAL_MANIFEST"] = path
    from app.credential_store import revoke, rotate
    try:
        if operation == "revoke":
            revoke("shared")
        else:
            rotate("shared", "worker", ["reader"], expires_at="2099-01-01T00:00:00Z", replacement_id="replacement")
        result_queue.put((operation, "ok"))
    except BaseException as exc:
        result_queue.put((operation, type(exc).__name__))


def _manifest(path, *, status="active", expires=None, credential_id="cred-1", token="manifest-secret"):
    expires = expires or (datetime.now(timezone.utc) + timedelta(days=1)).isoformat().replace("+00:00", "Z")
    path.write_text(json.dumps({
        "schemaVersion": 1, "manifestVersion": 1,
        "credentials": {credential_id: {
            "subject": "manifest-user", "digest": hashlib.sha256(token.encode()).hexdigest(),
            "status": status, "issuedAt": "2026-01-01T00:00:00Z", "expiresAt": expires,
            "roles": ["reader"], "tenantGrants": [],
        }},
    }), encoding="utf-8")
    return token


def test_manifest_active_credential_authenticates(monkeypatch, tmp_path):
    token = _manifest(tmp_path / "credentials.json")
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(tmp_path / "credentials.json"))
    with TestClient(app) as authenticated:
        assert authenticated.get("/audit/events", headers={"X-API-Key": token}).status_code == 200


@pytest.mark.parametrize("status", ["revoked", "superseded"])
def test_manifest_inactive_credentials_return_401(monkeypatch, tmp_path, status):
    token = _manifest(tmp_path / "credentials.json", status=status)
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(tmp_path / "credentials.json"))
    with TestClient(app) as authenticated:
        response = authenticated.get("/audit/events", headers={"X-API-Key": token})
    assert response.status_code == 401
    assert token not in response.text


def test_manifest_expired_and_unknown_credentials_return_401(monkeypatch, tmp_path):
    path = tmp_path / "credentials.json"
    expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    token = _manifest(path, expires=expired)
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    with TestClient(app) as authenticated:
        assert authenticated.get("/audit/events", headers={"X-API-Key": token}).status_code == 401
        assert authenticated.get("/audit/events", headers={"X-API-Key": "unknown"}).status_code == 401


def test_expiry_is_derived_and_rewrites_keep_manifest_valid(monkeypatch, tmp_path):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    expired_token = _manifest(path, expires=expired, credential_id="expired", token="expired-secret")
    document = json.loads(path.read_text(encoding="utf-8"))
    document["credentials"]["current"] = {
        "subject": "current", "digest": hashlib.sha256(b"current-secret").hexdigest(),
        "status": "active", "issuedAt": "2026-01-01T00:00:00Z",
        "expiresAt": "2099-01-01T00:00:00Z", "roles": ["reader"], "tenantGrants": [],
    }
    path.write_text(json.dumps(document), encoding="utf-8")

    # Loading and authenticating must not rewrite active to an unsupported
    # persisted `expired` state.
    assert load_manifest()["credentials"]["expired"]["status"] == "active"
    assert authenticate_for_test(expired_token) is None
    revoke("expired")
    staged = rotate("current", "current", ["reader"], expires_at="2099-01-01T00:00:00Z", replacement_id="replacement")
    assert staged
    rewritten = load_manifest()
    assert rewritten["credentials"]["expired"]["status"] == "revoked"
    assert rewritten["credentials"]["current"]["status"] == "active"
    assert rewritten["credentials"]["replacement"]["status"] == "staged"


def test_manifest_missing_or_malformed_production_authority_returns_503(monkeypatch, tmp_path):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_ENV", "production")
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    with TestClient(app) as authenticated:
        assert authenticated.get("/audit/events", headers={"X-API-Key": "anything"}).status_code == 503
    path.write_text("not-json", encoding="utf-8")
    with TestClient(app) as authenticated:
        assert authenticated.get("/audit/events", headers={"X-API-Key": "anything"}).status_code == 503


def test_manifest_authentication_logs_do_not_contain_secret_or_digest(monkeypatch, tmp_path, caplog):
    token = _manifest(tmp_path / "credentials.json")
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(tmp_path / "credentials.json"))
    with caplog.at_level("INFO", logger="audit.security"), TestClient(app) as authenticated:
        assert authenticated.get("/audit/events", headers={"X-API-Key": token + "-wrong"}).status_code == 401
    assert token not in caplog.text
    assert hashlib.sha256(token.encode()).hexdigest() not in caplog.text


def test_manifest_rotation_and_revocation_are_visible_without_cache(monkeypatch, tmp_path):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    first = provision("manifest-user", ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id="first")
    with TestClient(app) as authenticated:
        assert authenticated.get("/audit/events", headers={"X-API-Key": first}).status_code == 200
    replacement = rotate("first", "manifest-user", ["reader"], expires_at="2099-01-01T00:00:00Z", replacement_id="second")
    with TestClient(app) as authenticated:
        assert authenticated.get("/audit/events", headers={"X-API-Key": first}).status_code == 200
        assert authenticated.get("/audit/events", headers={"X-API-Key": replacement}).status_code == 401
    acknowledge_delivery("second")
    activate("second")
    with TestClient(app) as authenticated:
        assert authenticated.get("/audit/events", headers={"X-API-Key": first}).status_code == 401
        assert authenticated.get("/audit/events", headers={"X-API-Key": replacement}).status_code == 200
    revoke("second")
    with TestClient(app) as authenticated:
        assert authenticated.get("/audit/events", headers={"X-API-Key": replacement}).status_code == 401


def test_manifest_revocation_is_visible_to_independent_process(monkeypatch, tmp_path):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    token = provision("manifest-user", ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id="worker")
    revoke("worker")
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    process = context.Process(target=_manifest_auth_worker, args=(str(path), token, result_queue))
    process.start()
    process.join(timeout=10)
    assert process.exitcode == 0
    assert result_queue.get(timeout=2) is False
    result_queue.close()


def test_staged_credential_cannot_authenticate_before_delivery_ack(monkeypatch, tmp_path):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    first = provision("manifest-user", ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id="first")
    replacement = rotate("first", "manifest-user", ["reader"], expires_at="2099-01-01T00:00:00Z", replacement_id="second")
    assert authenticate_for_test(replacement) is None
    assert authenticate_for_test(first) is not None


def authenticate_for_test(token):
    from app.credential_store import authenticate
    return authenticate(token)


def test_operator_lock_timeout_fails_closed(monkeypatch, tmp_path):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    with _operator_lock(path):
        with pytest.raises(CredentialAuthorityError, match="timed out"):
            with _operator_lock(path, timeout=0.05):
                pass


def test_concurrent_initial_provisioning_preserves_both_updates(monkeypatch, tmp_path):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    processes = [context.Process(target=_provision_worker, args=(str(path), index, result_queue)) for index in range(2)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)
    assert all(process.exitcode == 0 for process in processes)
    assert sorted(result_queue.get(timeout=2) for _ in processes) == [(0, "ok"), (1, "ok")]
    result_queue.close()
    assert set(load_manifest_for_test()["credentials"]) == {"worker-0", "worker-1"}


def test_concurrent_rotation_and_revocation_do_not_lose_manifest_update(monkeypatch, tmp_path):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    provision("shared", ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id="shared")
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    processes = [
        context.Process(target=_rotate_or_revoke_worker, args=(str(path), operation, result_queue))
        for operation in ("rotate", "revoke")
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)
    assert all(process.exitcode == 0 for process in processes)
    results = sorted(result_queue.get(timeout=2) for _ in processes)
    assert {result[0] for result in results} == {"rotate", "revoke"}
    final = load_manifest_for_test()
    assert final["credentials"]["shared"]["status"] in {"revoked", "superseded"}
    if any(result == ("rotate", "ok") for result in results):
        assert final["credentials"]["replacement"]["status"] == "staged"
    result_queue.close()


def load_manifest_for_test():
    from app.credential_store import load_manifest
    return load_manifest()


def test_activation_directory_durability_failure_is_ambiguous_after_ack(monkeypatch, tmp_path):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    provision("manifest-user", ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id="first")
    replacement = rotate("first", "manifest-user", ["reader"], expires_at="2099-01-01T00:00:00Z", replacement_id="second")
    acknowledge_delivery("second")
    import app.credential_store as store
    original = store._durable_replace

    def replace_then_fail(target, document):
        original(target, document)
        raise OSError("directory fsync failure after replacement")

    monkeypatch.setattr(store, "_durable_replace", replace_then_fail)
    with pytest.raises(CredentialAuthorityError, match="ambiguous"):
        activate("second")
    # The replacement may already be authoritative; this is explicitly an
    # ambiguous outcome, not an unsafe claim that rollback succeeded.
    assert authenticate_for_test(replacement) is not None


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

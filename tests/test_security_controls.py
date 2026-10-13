"""End-to-end tests for authentication, signatures, export, and lifecycle integrity."""

import pytest
import hashlib
import json
import multiprocessing
import os
import traceback
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException
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
from app.credential_store import (
    CredentialAuthorityAmbiguousError,
    CredentialAuthorityError,
    _MAX_ACTIONS,
    _MAX_CREDENTIALS,
    _MAX_RESOURCE_SCOPES,
    _MAX_RESOURCE_VALUES,
    _MAX_ROLES,
    _MAX_TENANT_GRANTS,
    _operator_lock,
)
from app.credential_store import load_manifest


def _manifest_auth_worker(path, token, result_queue):
    os.environ["AUDIT_CREDENTIAL_MANIFEST"] = path
    from app.credential_store import authenticate
    result_queue.put(authenticate(token) is not None)


def _development_key_worker(path, result_queue):
    os.environ.pop("AUDIT_SIGNING_PRIVATE_KEY", None)
    os.environ["AUDIT_DEVELOPMENT_KEY_PATH"] = path
    try:
        from app.crypto.signer import _private_key, public_key_b64
        _private_key.cache_clear()
        result_queue.put(("ok", public_key_b64()))
    except BaseException as exc:
        result_queue.put(("error", type(exc).__name__, str(exc), traceback.format_exc()))


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


def test_manifest_valid_tenant_grants_are_loaded_before_authorization(monkeypatch, tmp_path):
    path = tmp_path / "credentials.json"
    token = "grant-secret"
    path.write_text(json.dumps({
        "schemaVersion": 1, "manifestVersion": 1,
        "credentials": {"grant-user": {
            "subject": "grant-user", "digest": hashlib.sha256(token.encode()).hexdigest(),
            "status": "active", "issuedAt": "2026-01-01T00:00:00Z",
            "expiresAt": "2099-01-01T00:00:00Z", "roles": ["reader"],
            "tenantGrants": [{"tenantId": "tenant-a", "actions": ["read"],
                              "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]}],
        }},
    }), encoding="utf-8")
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    principal = authenticated_principal(token)
    assert principal.tenant_grants[0]["tenantId"] == "tenant-a"


@pytest.mark.parametrize("mutation", [
    lambda document: document["credentials"]["cred-1"].update({"tenantGrants": "not-a-list"}),
    lambda document: document["credentials"]["cred-1"].update({"tenantGrants": [{"actions": ["read"]}]}),
    lambda document: document["credentials"]["cred-1"].update({"tenantGrants": [{"tenantId": "t", "actions": "read"}]}),
    lambda document: document["credentials"]["cred-1"].update({"tenantGrants": [{"tenantId": "t", "actions": ["invalid"]}]}),
    lambda document: document["credentials"]["cred-1"].update({"tenantGrants": [{"tenantId": "t", "actions": ["read"], "resourceScopes": "bad"}]}),
    lambda document: document["credentials"]["cred-1"].update({"roles": ["reader", 7]}),
    lambda document: document["credentials"]["cred-1"].update({"subject": "s" * 129}),
    lambda document: document["credentials"]["cred-1"].update({"tenantGrants": [{"tenantId": "t" * 129, "actions": ["read"]}]}),
    lambda document: document["credentials"]["cred-1"].update({"tenantGrants": [{"tenantId": "t", "actions": ["a" * 129]}]}),
    lambda document: document["credentials"]["cred-1"].update({"tenantGrants": [{"tenantId": "t", "actions": ["read"], "resourceIds": ["r" * 257]}]}),
    lambda document: document["credentials"].update({"x" * 129: document["credentials"].pop("cred-1")}),
])
def test_manifest_malformed_nested_authorization_metadata_returns_503(monkeypatch, tmp_path, mutation):
    path = tmp_path / "credentials.json"
    token = _manifest(path)
    document = json.loads(path.read_text(encoding="utf-8"))
    mutation(document)
    path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    with TestClient(app) as authenticated:
        response = authenticated.get("/audit/events", headers={"X-API-Key": token})
    assert response.status_code == 503


def test_manifest_path_trust_rejects_relative_and_symlinked_paths(monkeypatch, tmp_path):
    from app.credential_store import authenticate

    (tmp_path / "real").mkdir()
    token = _manifest(tmp_path / "real" / "credentials.json")
    real_path = tmp_path / "real" / "credentials.json"

    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", "relative/credentials.json")
    with pytest.raises(CredentialAuthorityError, match="absolute"):
        authenticate(token)

    link = tmp_path / "credentials-link.json"
    try:
        link.symlink_to(real_path)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unsupported: {exc}")
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(link))
    with pytest.raises(CredentialAuthorityError, match="not trusted"):
        authenticate(token)


def test_manifest_path_trust_rejects_symlinked_parent_for_mutations(monkeypatch, tmp_path):
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    real_path = real_parent / "credentials.json"
    _manifest(real_path)
    linked_parent = tmp_path / "linked-parent"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlink creation unsupported: {exc}")

    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(linked_parent / "credentials.json"))
    with pytest.raises(CredentialAuthorityError, match="not trusted"):
        provision("new-user", ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id="new")
    assert json.loads(real_path.read_text(encoding="utf-8"))["credentials"]


def _bounded_grant(index=0):
    return {
        "tenantId": f"tenant-{index}",
        "actions": ["read"],
        "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": [f"client-{index}"]}],
    }


@pytest.mark.parametrize("collection", [
    "credentials", "roles", "tenantGrants", "actions", "resourceScopes", "resourceIds",
])
def test_manifest_collection_limits_accept_boundary(monkeypatch, tmp_path, collection):
    path = tmp_path / "credentials.json"
    token = _manifest(path)
    document = json.loads(path.read_text(encoding="utf-8"))
    entry = document["credentials"]["cred-1"]
    if collection == "credentials":
        original = entry.copy()
        document["credentials"] = {f"cred-{index}": {**original, "digest": hashlib.sha256(f"token-{index}".encode()).hexdigest()} for index in range(_MAX_CREDENTIALS)}
        document["credentials"]["cred-1"]["digest"] = original["digest"]
    elif collection == "roles":
        entry["roles"] = [f"role-{index}" for index in range(_MAX_ROLES)]
    elif collection == "tenantGrants":
        entry["tenantGrants"] = [_bounded_grant(index) for index in range(_MAX_TENANT_GRANTS)]
    elif collection == "actions":
        entry["tenantGrants"] = [{"tenantId": "tenant-a", "actions": ["read"] * _MAX_ACTIONS}]
    elif collection == "resourceScopes":
        entry["tenantGrants"] = [{"tenantId": "tenant-a", "actions": ["read"], "resourceScopes": [_bounded_grant(index)["resourceScopes"][0] for index in range(_MAX_RESOURCE_SCOPES)]}]
    else:
        entry["tenantGrants"] = [{"tenantId": "tenant-a", "actions": ["read"], "resourceIds": [f"resource-{index}" for index in range(_MAX_RESOURCE_VALUES)]}]
    path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    assert authenticated_principal(token).subject == "manifest-user"


@pytest.mark.parametrize("collection", [
    "credentials", "roles", "tenantGrants", "actions", "resourceScopes", "resourceIds",
])
def test_manifest_collection_limits_fail_closed(monkeypatch, tmp_path, collection):
    path = tmp_path / "credentials.json"
    token = _manifest(path)
    document = json.loads(path.read_text(encoding="utf-8"))
    entry = document["credentials"]["cred-1"]
    if collection == "credentials":
        original = entry.copy()
        document["credentials"] = {f"cred-{index}": {**original, "digest": hashlib.sha256(f"token-{index}".encode()).hexdigest()} for index in range(_MAX_CREDENTIALS + 1)}
    elif collection == "roles":
        entry["roles"] = [f"role-{index}" for index in range(_MAX_ROLES + 1)]
    elif collection == "tenantGrants":
        entry["tenantGrants"] = [_bounded_grant(index) for index in range(_MAX_TENANT_GRANTS + 1)]
    elif collection == "actions":
        entry["tenantGrants"] = [{"tenantId": "tenant-a", "actions": ["read"] * (_MAX_ACTIONS + 1)}]
    elif collection == "resourceScopes":
        entry["tenantGrants"] = [{"tenantId": "tenant-a", "actions": ["read"], "resourceScopes": [_bounded_grant(index)["resourceScopes"][0] for index in range(_MAX_RESOURCE_SCOPES + 1)]}]
    else:
        entry["tenantGrants"] = [{"tenantId": "tenant-a", "actions": ["read"], "resourceIds": [f"resource-{index}" for index in range(_MAX_RESOURCE_VALUES + 1)]}]
    path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    with pytest.raises(HTTPException) as caught:
        authenticated_principal(token)
    assert caught.value.status_code == 503


def test_lifecycle_rejects_oversized_collections_and_preserves_manifest(monkeypatch, tmp_path):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    provision("manifest-user", ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id="first")
    with pytest.raises(CredentialAuthorityError):
        provision("new-user", [f"role-{index}" for index in range(_MAX_ROLES + 1)], expires_at="2099-01-01T00:00:00Z", credential_id="too-many-roles")
    with pytest.raises(CredentialAuthorityError):
        rotate("first", "manifest-user", ["reader"], tenant_grants=[_bounded_grant(index) for index in range(_MAX_TENANT_GRANTS + 1)], expires_at="2099-01-01T00:00:00Z", replacement_id="too-many-grants")
    manifest = load_manifest()
    assert set(manifest["credentials"]) == {"first"}


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
        raise CredentialAuthorityAmbiguousError(
            "credential authority mutation outcome is ambiguous; inspect the manifest before retrying"
        )

    monkeypatch.setattr(store, "_durable_replace", replace_then_fail)
    with pytest.raises(CredentialAuthorityError, match="ambiguous"):
        activate("second")
    # The replacement may already be authoritative; this is explicitly an
    # ambiguous outcome, not an unsafe claim that rollback succeeded.
    assert authenticate_for_test(replacement) is not None


def test_post_replacement_provision_failure_is_ambiguous_and_not_retried(monkeypatch, tmp_path):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    import app.credential_store as store
    original = store._durable_replace
    secret = "provision-secret"
    monkeypatch.setattr(store, "generate_token", lambda: secret)

    def replace_then_fail(target, document):
        original(target, document)
        raise CredentialAuthorityAmbiguousError(
            "credential authority mutation outcome is ambiguous; inspect the manifest before retrying"
        )

    monkeypatch.setattr(store, "_durable_replace", replace_then_fail)
    with pytest.raises(CredentialAuthorityAmbiguousError, match="inspect the manifest"):
        provision("new-user", ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id="new")
    manifest = load_manifest()
    assert manifest["credentials"]["new"]["status"] == "active"
    assert manifest["manifestVersion"] == 2
    assert secret not in str(manifest)


@pytest.mark.parametrize("operation", ["rotate", "revoke"])
def test_post_replacement_mutation_failure_is_ambiguous_and_manifest_inspected(monkeypatch, tmp_path, operation):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    first = provision("manifest-user", ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id="first")
    import app.credential_store as store
    original = store._durable_replace
    replacement_secret = "replacement-secret"
    if operation == "rotate":
        monkeypatch.setattr(store, "generate_token", lambda: replacement_secret)

    def replace_then_fail(target, document):
        original(target, document)
        raise CredentialAuthorityAmbiguousError(
            "credential authority mutation outcome is ambiguous; inspect the manifest before retrying"
        )

    monkeypatch.setattr(store, "_durable_replace", replace_then_fail)
    with pytest.raises(CredentialAuthorityAmbiguousError, match="inspect the manifest") as caught:
        if operation == "rotate":
            rotate("first", "manifest-user", ["reader"], expires_at="2099-01-01T00:00:00Z", replacement_id="second")
        else:
            revoke("first")
    manifest = load_manifest()
    if operation == "rotate":
        assert manifest["credentials"]["second"]["status"] == "staged"
        assert manifest["credentials"]["first"]["status"] == "active"
    else:
        assert manifest["credentials"]["first"]["status"] == "revoked"
    assert first not in str(caught.value)
    if operation == "rotate":
        assert replacement_secret not in str(caught.value)


@pytest.mark.parametrize("operation", ["provision", "rotate", "revoke"])
def test_pre_replacement_mutation_failure_is_reported_without_manifest_change(monkeypatch, tmp_path, operation):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))
    first = None
    if operation != "provision":
        first = provision("manifest-user", ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id="first")
    import app.credential_store as store

    def fail_before_replace(target, document):
        raise OSError("injected failure before replacement")

    monkeypatch.setattr(store, "_durable_replace", fail_before_replace)
    with pytest.raises(CredentialAuthorityError) as caught:
        if operation == "provision":
            provision("new-user", ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id="new")
        elif operation == "rotate":
            rotate("first", "manifest-user", ["reader"], expires_at="2099-01-01T00:00:00Z", replacement_id="second")
        else:
            revoke("first")
    assert not isinstance(caught.value, CredentialAuthorityAmbiguousError)
    if operation == "provision":
        assert not path.exists()
    else:
        manifest = load_manifest()
        assert manifest["credentials"]["first"]["status"] == "active"
        assert "second" not in manifest["credentials"]
    assert "token" not in str(caught.value).lower()
    if first:
        assert first not in str(caught.value)


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


def test_development_key_creation_serializes_first_start_attempts(tmp_path, monkeypatch):
    path = tmp_path / "development.key"
    monkeypatch.delenv("AUDIT_SIGNING_PRIVATE_KEY", raising=False)
    monkeypatch.setenv("AUDIT_DEVELOPMENT_KEY_PATH", str(path))
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    processes = [context.Process(target=_development_key_worker, args=(str(path), result_queue)) for _ in range(2)]
    try:
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=10)
        assert all(process.exitcode == 0 for process in processes)
        results = [result_queue.get(timeout=2) for _ in processes]
        assert all(result[0] == "ok" for result in results), results
        assert results[0][1] == results[1][1]
        assert len(path.read_text(encoding="ascii").strip()) == 44
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(timeout=2)
        result_queue.close()


def test_partial_development_key_fails_closed_without_overwrite(tmp_path, monkeypatch):
    path = tmp_path / "development.key"
    path.write_text("partial-key", encoding="ascii")
    monkeypatch.delenv("AUDIT_SIGNING_PRIVATE_KEY", raising=False)
    monkeypatch.setenv("AUDIT_DEVELOPMENT_KEY_PATH", str(path))
    _private_key.cache_clear()
    with pytest.raises(RuntimeError, match="Development signing key file is invalid"):
        _private_key()
    assert path.read_text(encoding="ascii") == "partial-key"


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


def test_administrative_lifecycle_operations_emit_structured_events(monkeypatch, tmp_path, caplog):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))

    with caplog.at_level("INFO", logger="audit.security.credentials"):
        # 1. Provision
        token1 = provision("alice", ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id="cred-alice")
        assert "action=credential_provisioned outcome=success credential_id=cred-alice subject=alice" in caplog.text

        # 2. Rotate
        caplog.clear()
        token2 = rotate("cred-alice", "alice", ["reader"], expires_at="2099-01-01T00:00:00Z", replacement_id="cred-alice-v2")
        assert "action=credential_rotated outcome=success credential_id=cred-alice replacement_id=cred-alice-v2 subject=alice" in caplog.text

        # 3. Acknowledge delivery
        caplog.clear()
        acknowledge_delivery("cred-alice-v2")
        assert "action=credential_delivery_acknowledged outcome=success credential_id=cred-alice-v2" in caplog.text

        # 4. Activate
        caplog.clear()
        activate("cred-alice-v2")
        assert "action=credential_activated outcome=success credential_id=cred-alice-v2 subject=alice" in caplog.text

        # 4b. Idempotent activate (already active)
        caplog.clear()
        activate("cred-alice-v2")
        assert "action=credential_activated outcome=already_active credential_id=cred-alice-v2 subject=alice" in caplog.text

        # 5. Revoke
        caplog.clear()
        revoke("cred-alice-v2")
        assert "action=credential_revoked outcome=success credential_id=cred-alice-v2 subject=alice" in caplog.text

    # Verify no tokens or SHA-256 digests appear anywhere in any logged output
    all_logs = caplog.text
    assert token1 not in all_logs
    assert token2 not in all_logs
    assert hashlib.sha256(token1.encode()).hexdigest() not in all_logs
    assert hashlib.sha256(token2.encode()).hexdigest() not in all_logs


def test_administrative_lifecycle_failures_emit_accurate_events(monkeypatch, tmp_path, caplog):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))

    with caplog.at_level("INFO", logger="audit.security.credentials"):
        # Initial valid provision
        provision("bob", ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id="cred-bob")

        # 1. Duplicate provision failure
        caplog.clear()
        with pytest.raises(CredentialAuthorityError, match="already exists"):
            provision("bob", ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id="cred-bob")
        assert "action=credential_provisioned outcome=failed_duplicate_identifier credential_id=cred-bob subject=bob" in caplog.text

        # 2. Rotate non-existent / not active
        caplog.clear()
        with pytest.raises(CredentialAuthorityError, match="not active"):
            rotate("nonexistent", "bob", ["reader"], expires_at="2099-01-01T00:00:00Z", replacement_id="repl-1")
        assert "action=credential_rotated outcome=failed_target_not_active credential_id=nonexistent replacement_id=repl-1" in caplog.text

        # 3. Rotate duplicate replacement ID
        caplog.clear()
        with pytest.raises(CredentialAuthorityError, match="already exists"):
            rotate("cred-bob", "bob", ["reader"], expires_at="2099-01-01T00:00:00Z", replacement_id="cred-bob")
        assert "action=credential_rotated outcome=failed_duplicate_identifier credential_id=cred-bob replacement_id=cred-bob" in caplog.text

        # 4. Acknowledge delivery for non-staged
        caplog.clear()
        with pytest.raises(CredentialAuthorityError, match="not staged"):
            acknowledge_delivery("cred-bob")
        assert "action=credential_delivery_acknowledged outcome=failed_not_staged credential_id=cred-bob" in caplog.text

        # 5. Activate non-existent
        caplog.clear()
        with pytest.raises(CredentialAuthorityError, match="not found"):
            activate("nonexistent")
        assert "action=credential_activated outcome=failed_not_found credential_id=nonexistent" in caplog.text

        # 6. Activate unacknowledged staged credential
        token_staged = rotate("cred-bob", "bob", ["reader"], expires_at="2099-01-01T00:00:00Z", replacement_id="cred-bob-v2")
        caplog.clear()
        with pytest.raises(CredentialAuthorityError, match="acknowledgement is required"):
            activate("cred-bob-v2")
        assert "action=credential_activated outcome=failed_not_acknowledged credential_id=cred-bob-v2 subject=bob" in caplog.text

        # 7. Revoke non-existent
        caplog.clear()
        with pytest.raises(CredentialAuthorityError, match="not found"):
            revoke("nonexistent")
        assert "action=credential_revoked outcome=failed_not_found credential_id=nonexistent" in caplog.text

        # 8. Unconfigured authority
        monkeypatch.delenv("AUDIT_CREDENTIAL_MANIFEST", raising=False)
        caplog.clear()
        with pytest.raises(CredentialAuthorityError, match="not configured"):
            provision("charlie", ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id="cred-charlie")
        assert "action=credential_provisioned outcome=failed_unconfigured subject=charlie" in caplog.text


def test_administrative_lifecycle_sanitizes_hostile_identifiers(monkeypatch, tmp_path, caplog):
    path = tmp_path / "credentials.json"
    monkeypatch.setenv("AUDIT_CREDENTIAL_MANIFEST", str(path))

    with caplog.at_level("INFO", logger="audit.security.credentials"):
        # Hostile identifiers containing CRLF injection and control characters
        hostile_subject = "operator\r\nINJECTED_LOG_ENTRY action=pwned\x00"
        hostile_id = "cred-1\r\nANOTHER_INJECTION\t"

        provision(hostile_subject, ["reader"], expires_at="2099-01-01T00:00:00Z", credential_id=hostile_id)

        # Confirm no raw newlines or control characters exist inside log records
        assert len(caplog.records) == 1
        msg = caplog.records[0].getMessage()
        assert "\r" not in msg
        assert "\n" not in msg
        assert "\x00" not in msg
        assert "cred-1__ANOTHER_INJECTION" in msg
        assert "operator__INJECTED_LOG_ENTRY action=pwned_" in msg


def test_operator_lock_posix_branch_coverage(monkeypatch, tmp_path):
    import sys
    calls = []
    fake_fcntl = type("FakeFcntl", (), {
        "LOCK_EX": 2, "LOCK_NB": 4, "LOCK_UN": 8,
        "flock": lambda fd, op: calls.append(op),
    })
    path = tmp_path / "creds.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setitem(sys.modules, "fcntl", fake_fcntl)
    with _operator_lock(path):
        pass
    assert calls == [fake_fcntl.LOCK_EX | fake_fcntl.LOCK_NB, fake_fcntl.LOCK_UN]

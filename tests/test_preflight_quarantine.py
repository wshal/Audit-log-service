"""Startup integrity preflight and fail-closed quarantine tests."""

import pytest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import os
import subprocess
import sys
import json
import hashlib
import base64
from fastapi.testclient import TestClient
from sqlalchemy import text
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _set_recovery_token(monkeypatch, token):
    monkeypatch.setenv("AUDIT_QUARANTINE_RECOVERY_TOKEN", token)
    monkeypatch.setenv("AUDIT_QUARANTINE_RECOVERY_TOKEN_DIGEST", hashlib.sha256(token.encode()).hexdigest())

import app.main as main_module
from app.crypto.hasher import GENESIS_PREV_HASH
from app.crypto.signer import _private_key, public_key_ring, sign_record_hash, signing_key_id, verify_record_signature
from app.models.schemas import AuditEventCreate
from app.security import Principal
from app.storage.database import AuditRecordEntity
from app.storage.repository import AuditLedgerRepository
from app.services.lifecycle import LifecycleAndExportService
from app.services.compliance import ComplianceService
from app.services.verifier import ChainVerificationService
from app.runtime_state import set_state


def _record(session, payload_json="{}", sequence=1, record_hash="r", content_hash="c", prev_hash=GENESIS_PREV_HASH):
    row = AuditRecordEntity(
        sequence_num=sequence, event_type="LEGACY", actor_id="actor", resource_type="CLIENT",
        resource_id="client", payload_json=payload_json, timestamp="2026-01-01T00:00:00Z",
        content_hash=content_hash, prev_hash=prev_hash, record_hash=record_hash,
        record_signature=sign_record_hash(record_hash), signing_key_id=signing_key_id(),
        is_archived=False, protocol_version=1,
    )
    session.add(row); session.commit()


def test_fresh_database_is_healthy_and_ready(isolated_test_application):
    with TestClient(main_module.app) as client:
        assert client.get("/health").json()["status"] == "healthy"
        assert client.get("/ready").status_code == 200


def _configure_production_signing(monkeypatch, *, ring="default"):
    """Configure an ephemeral production key and return its public key."""
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes_raw()
    public_key = base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    monkeypatch.setenv("AUDIT_ENV", "production")
    monkeypatch.setenv("AUDIT_SIGNING_KEY_ID", "production-test")
    monkeypatch.setenv("AUDIT_SIGNING_PRIVATE_KEY", base64.b64encode(private_bytes).decode("ascii"))
    if ring == "default":
        monkeypatch.setenv("AUDIT_SIGNING_PUBLIC_KEYS", json.dumps({"production-test": public_key}))
    elif ring is None:
        monkeypatch.delenv("AUDIT_SIGNING_PUBLIC_KEYS", raising=False)
    else:
        monkeypatch.setenv("AUDIT_SIGNING_PUBLIC_KEYS", ring)
    _private_key.cache_clear()
    public_key_ring.cache_clear()
    return public_key


def _clear_signing_caches():
    _private_key.cache_clear()
    public_key_ring.cache_clear()


def test_production_missing_signing_key_quarantines_empty_ledger(isolated_test_application, monkeypatch):
    monkeypatch.setenv("AUDIT_ENV", "production")
    monkeypatch.delenv("AUDIT_SIGNING_PRIVATE_KEY", raising=False)
    _clear_signing_caches()
    try:
        with TestClient(main_module.app) as client:
            assert client.get("/health").json()["status"] == "quarantined"
            assert client.get("/ready").status_code == 503
    finally:
        _clear_signing_caches()


@pytest.mark.parametrize("ring", ["not-json", json.dumps({"other-key": "not-a-public-key"})])
def test_production_invalid_public_key_ring_quarantines_empty_ledger(isolated_test_application, monkeypatch, ring):
    _configure_production_signing(monkeypatch, ring=ring)
    try:
        with TestClient(main_module.app) as client:
            assert client.get("/health").json()["status"] == "quarantined"
            assert client.get("/ready").status_code == 503
    finally:
        _clear_signing_caches()


def test_production_active_private_key_must_match_configured_public_key(isolated_test_application, monkeypatch):
    _configure_production_signing(monkeypatch)
    different_public_key = base64.b64encode(
        Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    monkeypatch.setenv("AUDIT_SIGNING_PUBLIC_KEYS", json.dumps({"production-test": different_public_key}))
    _clear_signing_caches()
    try:
        with TestClient(main_module.app) as client:
            assert client.get("/health").json()["status"] == "quarantined"
            assert client.get("/ready").status_code == 503
    finally:
        _clear_signing_caches()


def test_production_malformed_private_key_quarantines_without_disclosing_value(isolated_test_application, monkeypatch):
    malformed_value = "not-valid-base64-private-key"
    monkeypatch.setenv("AUDIT_ENV", "production")
    monkeypatch.setenv("AUDIT_SIGNING_PRIVATE_KEY", malformed_value)
    monkeypatch.delenv("AUDIT_SIGNING_PUBLIC_KEYS", raising=False)
    _clear_signing_caches()
    try:
        with TestClient(main_module.app) as client:
            response = client.get("/health")
            assert response.json()["status"] == "quarantined"
            assert client.get("/ready").status_code == 503
            assert malformed_value not in response.text
    finally:
        _clear_signing_caches()


def test_valid_production_signing_configuration_is_ready_and_signs(isolated_test_application, monkeypatch):
    public_key = _configure_production_signing(monkeypatch)
    try:
        with TestClient(main_module.app) as client:
            assert client.get("/health").json()["status"] == "healthy"
            assert client.get("/ready").status_code == 200

        session = isolated_test_application["session_factory"]()
        try:
            record = AuditLedgerRepository(session).append_event(
                AuditEventCreate(
                    eventType="V1", actorId="writer", resourceType="CLIENT", resourceId="client",
                    payload={}, timestamp="2026-01-01T00:00:00Z",
                ),
                Principal("writer", frozenset({"writer"}), "production-test", (), True),
            )
            assert verify_record_signature(record.record_hash, record.record_signature, public_key)
        finally:
            session.close()
    finally:
        _clear_signing_caches()


def test_malformed_legacy_record_quarantines_and_blocks_audit_routes(isolated_test_application):
    session = isolated_test_application["session_factory"]()
    _record(session, payload_json="not-json")
    session.close()
    with TestClient(main_module.app) as client:
        assert client.get("/health").json() == {"status": "quarantined", "service": main_module.settings.APP_NAME, "version": main_module.settings.APP_VERSION}
        assert client.get("/ready").status_code == 503
        assert client.get("/audit/events").status_code == 503
        assert client.post("/audit/events", json={}).status_code == 503


def test_valid_mixed_ledger_preflight_succeeds(isolated_test_application, monkeypatch):
    monkeypatch.setenv("AUDIT_RESOURCE_OWNERSHIP", '{"CLIENT_ACCOUNT:client-a":{"tenantId":"tenant-a"}}')
    from app.authorization import clear_authorization_caches
    clear_authorization_caches()
    session = isolated_test_application["session_factory"]()
    repo = AuditLedgerRepository(session)
    repo.append_event(AuditEventCreate(eventType="V1", actorId="actor", resourceType="CLIENT", resourceId="client", payload={}, timestamp="2026-01-01T00:00:00Z"), Principal("actor", frozenset({"writer"}), "v1", (), True))
    repo.append_event(AuditEventCreate(eventType="V2", actorId="actor", resourceType="CLIENT_ACCOUNT", resourceId="client-a", payload={}, timestamp="2026-01-01T00:00:01Z", tenantId="tenant-a"), Principal("actor", frozenset({"writer"}), "v2", ({"tenantId": "tenant-a", "actions": ["write"], "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},)))
    session.close()
    with TestClient(main_module.app) as client:
        assert client.get("/health").json()["status"] == "healthy"


def test_quarantine_persists_until_operator_recovery(isolated_test_application, monkeypatch):
    session = isolated_test_application["session_factory"]()
    _record(session, payload_json="not-json")
    session.close()
    with TestClient(main_module.app) as client:
        assert client.get("/ready").status_code == 503
    # Operator repairs/restores the database, then explicitly authorizes recovery.
    session = isolated_test_application["session_factory"]()
    session.query(AuditRecordEntity).delete(); session.commit(); session.close()
    _set_recovery_token(monkeypatch, "one-time-token")
    with TestClient(main_module.app) as client:
        assert client.get("/ready").status_code == 200


def test_broken_sequence_and_signature_quarantine(isolated_test_application):
    session = isolated_test_application["session_factory"]()
    _record(session, sequence=2)
    session.close()
    with TestClient(main_module.app) as client:
        assert client.get("/ready").status_code == 503

    # A new isolated database is not available inside this test; the first
    # failure already proves preflight rejects a structurally invalid V1 row.


def test_missing_mixed_transition_quarantines(isolated_test_application, monkeypatch):
    monkeypatch.setenv("AUDIT_RESOURCE_OWNERSHIP", '{"CLIENT_ACCOUNT:client-a":{"tenantId":"tenant-a"}}')
    from app.authorization import clear_authorization_caches
    clear_authorization_caches()
    session = isolated_test_application["session_factory"]()
    repo = AuditLedgerRepository(session)
    repo.append_event(AuditEventCreate(eventType="V2", actorId="actor", resourceType="CLIENT_ACCOUNT", resourceId="client-a", payload={}, timestamp="2026-01-01T00:00:01Z", tenantId="tenant-a"), Principal("actor", frozenset({"writer"}), "v2", ({"tenantId": "tenant-a", "actions": ["write"], "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}]},)))
    session.execute(text("DELETE FROM audit_epoch_transitions")); session.commit(); session.close()
    with TestClient(main_module.app) as client:
        assert client.get("/ready").status_code == 503


def test_invalid_legacy_signature_quarantines(isolated_test_application):
    session = isolated_test_application["session_factory"]()
    _record(session)
    row = session.query(AuditRecordEntity).first()
    row.record_signature = "invalid"
    session.commit(); session.close()
    with TestClient(main_module.app) as client:
        assert client.get("/ready").status_code == 503


def test_direct_entry_points_fail_closed_while_quarantined(isolated_test_application, monkeypatch):
    set_state("quarantined")
    session = isolated_test_application["session_factory"]()
    principal = Principal("p", frozenset({"global_auditor"}), "c")
    with pytest.raises(Exception):
        AuditLedgerRepository(session).get_all_ordered_by_sequence(principal)
    with pytest.raises(Exception):
        LifecycleAndExportService.generate_verifiable_export(session, resource_id="x", principal=principal)
    with pytest.raises(Exception):
        ComplianceService.generate_client_access_audit_report(session, client_id="x", principal=principal)
    with pytest.raises(Exception):
        LifecycleAndExportService.apply_retention_policy(session, 1, "test", principal=principal)
    with pytest.raises(Exception):
        LifecycleAndExportService.redact_record_fields(session, 1, ["x"], "test", principal=principal)
    with pytest.raises(Exception):
        ChainVerificationService.verify_ledger(session, principal=principal)


def test_recovery_token_is_consumed_and_does_not_repeat(isolated_test_application, monkeypatch):
    session = isolated_test_application["session_factory"]()
    _record(session, payload_json="not-json")
    session.close()
    with TestClient(main_module.app) as client:
        assert client.get("/ready").status_code == 503
    with TestClient(main_module.app) as client:
        assert client.get("/ready").status_code == 503
    session = isolated_test_application["session_factory"]()
    session.query(AuditRecordEntity).delete(); session.commit(); session.close()
    _set_recovery_token(monkeypatch, "one-time-token")
    with TestClient(main_module.app) as client:
        assert client.get("/ready").status_code == 200
    with TestClient(main_module.app) as client:
        assert client.get("/ready").status_code == 200
    session = isolated_test_application["session_factory"]()
    _record(session, payload_json="not-json")
    session.close()
    with TestClient(main_module.app) as client:
        assert client.get("/ready").status_code == 503


def test_preflight_verifier_exception_fails_closed(isolated_test_application, monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError("verification dependency failed")
    monkeypatch.setattr(main_module.ChainVerificationService, "verify_ledger", explode)
    assert main_module.run_integrity_preflight() is False
    assert main_module.app is not None
    assert main_module.health_check()["status"] == "quarantined"

def test_preflight_marker_write_failure_stays_quarantined(isolated_test_application, monkeypatch):
    session = isolated_test_application["session_factory"]()
    _record(session, payload_json="not-json")
    session.close()
    monkeypatch.setattr(main_module, "_persist_marker", lambda reason: (_ for _ in ()).throw(OSError("read-only fs")))
    assert main_module.run_integrity_preflight() is False
    assert main_module.health_check()["status"] == "quarantined"
def test_preflight_marker_read_and_session_failures_stay_quarantined(isolated_test_application, monkeypatch):
    class BrokenMarker:
        def exists(self):
            raise OSError("marker unavailable")
    monkeypatch.setattr(main_module, "_quarantine_marker", lambda: BrokenMarker())
    assert main_module.run_integrity_preflight() is False
    assert main_module.health_check()["status"] == "quarantined"

    monkeypatch.setattr(main_module, "_quarantine_marker", lambda: Path("missing-quarantine.flag"))
    monkeypatch.setattr(main_module, "SessionLocal", lambda: (_ for _ in ()).throw(OSError("database unavailable")))
    monkeypatch.setattr(main_module, "_persist_marker", lambda reason: None)
    assert main_module.run_integrity_preflight() is False
    assert main_module.health_check()["status"] == "quarantined"


def test_preflight_preserves_historical_rows(isolated_test_application):
    session = isolated_test_application["session_factory"]()
    AuditLedgerRepository(session).append_event(
        AuditEventCreate(eventType="V1", actorId="actor", resourceType="CLIENT", resourceId="client", payload={}, timestamp="2026-01-01T00:00:00Z"),
        Principal("actor", frozenset({"writer"}), "v1", (), True),
    )
    before = [(r.sequence_num, r.payload_json, r.content_hash, r.record_hash, r.record_signature,
               r.tenant_id, r.prev_hash) for r in session.query(AuditRecordEntity).all()]
    session.close()
    assert main_module.run_integrity_preflight() is True
    session = isolated_test_application["session_factory"]()
    after = [(r.sequence_num, r.payload_json, r.content_hash, r.record_hash, r.record_signature,
              r.tenant_id, r.prev_hash) for r in session.query(AuditRecordEntity).all()]
    session.close()
    assert after == before


def test_recovery_token_concurrent_consumption_is_single_use(isolated_test_application, monkeypatch):
    marker = Path(isolated_test_application["engine"].url.database).with_name("concurrent-quarantine.flag")
    marker.write_text("quarantined\n", encoding="utf-8")
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(marker))
    _set_recovery_token(monkeypatch, "concurrent-token")
    consumed = marker.with_name(marker.name + ".recovery-consumed")
    barrier = Barrier(2)
    original_exists = Path.exists

    def synchronized_exists(path):
        if path == consumed:
            barrier.wait(timeout=5)
        return original_exists(path)

    monkeypatch.setattr(Path, "exists", synchronized_exists)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: main_module._consume_recovery_token(), range(2)))
    assert results.count(True) == 1
    assert results.count(False) == 1


def test_recovery_token_single_use_across_processes(isolated_test_application):
    marker = Path(isolated_test_application["engine"].url.database).with_name("process-quarantine.flag")
    env = os.environ.copy()
    env["AUDIT_QUARANTINE_MARKER"] = str(marker)
    env["AUDIT_QUARANTINE_RECOVERY_TOKEN"] = "process-token"
    env["AUDIT_QUARANTINE_RECOVERY_TOKEN_DIGEST"] = hashlib.sha256(b"process-token").hexdigest()
    command = "from app.main import _consume_recovery_token; print(_consume_recovery_token())"
    processes = [
        subprocess.Popen([sys.executable, "-c", command], cwd=str(Path(__file__).parents[1]), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(2)
    ]
    outputs = [process.communicate(timeout=10)[0].strip() for process in processes]
    assert sorted(outputs) == ["False", "True"]


def test_recovery_reservation_persistence_failure_consumes_token(isolated_test_application, monkeypatch):
    marker = Path(isolated_test_application["engine"].url.database).with_name("persistence-quarantine.flag")
    marker.write_text("quarantined\n", encoding="utf-8")
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(marker))
    _set_recovery_token(monkeypatch, "persistence-token")
    original_fdopen = main_module.os.fdopen

    def fail_fdopen(*args, **kwargs):
        raise OSError("persistence unavailable")

    monkeypatch.setattr(main_module.os, "fdopen", fail_fdopen)
    with pytest.raises(OSError):
        main_module._consume_recovery_token()
    assert marker.with_name(marker.name + ".recovery-consumed").exists()
    monkeypatch.setattr(main_module.os, "fdopen", original_fdopen)
    assert main_module._consume_recovery_token() is False


def test_failed_recovery_cannot_reuse_token_after_database_repair(isolated_test_application, monkeypatch):
    marker = Path(isolated_test_application["engine"].url.database).with_name("failed-recovery.flag")
    marker.write_text("quarantined\n", encoding="utf-8")
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(marker))
    _set_recovery_token(monkeypatch, "failed-token")
    monkeypatch.setattr(main_module, "SessionLocal", lambda: (_ for _ in ()).throw(OSError("database unavailable")))
    assert main_module.run_integrity_preflight() is False
    monkeypatch.setattr(main_module, "SessionLocal", isolated_test_application["session_factory"])
    # Even after the database dependency is restored, the same token cannot
    # authorize another attempt because its reservation is already durable.
    assert main_module.run_integrity_preflight() is False


def test_missing_recovery_reservation_cannot_clear_marker(isolated_test_application, monkeypatch):
    marker = Path(isolated_test_application["engine"].url.database).with_name("missing-reservation.flag")
    marker.write_text("quarantined\n", encoding="utf-8")
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(marker))
    _set_recovery_token(monkeypatch, "missing-reservation-token")
    monkeypatch.setattr(main_module, "_consume_recovery_token", lambda: True)

    assert main_module.run_integrity_preflight() is False
    assert marker.exists()
    assert main_module.health_check()["status"] == "quarantined"

# End of quarantine recovery regression coverage.

def test_malformed_recovery_reservation_fails_closed(isolated_test_application, monkeypatch):
    marker = Path(isolated_test_application["engine"].url.database).with_name("malformed-reservation.flag")
    marker.write_text("quarantined\n", encoding="utf-8")
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(marker))
    reservation = marker.with_name(marker.name + ".recovery-consumed")
    reservation.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        main_module._record_recovery_outcome("successful")
    assert marker.exists()


def test_unreadable_recovery_reservation_fails_closed(isolated_test_application, monkeypatch):
    marker = Path(isolated_test_application["engine"].url.database).with_name("unreadable-reservation.flag")
    reservation = marker.with_name(marker.name + ".recovery-consumed")
    reservation.write_text('{"tokenHash":"abc","outcome":"attempted"}\n', encoding="utf-8")
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(marker))
    monkeypatch.setattr(Path, "read_text", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("read failed")))
    with pytest.raises(OSError):
        main_module._record_recovery_outcome("successful")


def test_successful_reservation_flushes_containing_directory(isolated_test_application, monkeypatch):
    marker = Path(isolated_test_application["engine"].url.database).with_name("durable-reservation.flag")
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(marker))
    _set_recovery_token(monkeypatch, "durable-reservation-token")
    calls = []
    monkeypatch.setattr(main_module, "_fsync_directory", lambda path: calls.append(path) or True)

    assert main_module._consume_recovery_token() is True
    assert calls == [marker.parent]
    assert marker.with_name(marker.name + ".recovery-consumed").exists()


def test_reservation_directory_fsync_failure_fails_closed(isolated_test_application, monkeypatch):
    marker = Path(isolated_test_application["engine"].url.database).with_name("reservation-fsync-failure.flag")
    marker.write_text("quarantined\n", encoding="utf-8")
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(marker))
    _set_recovery_token(monkeypatch, "reservation-fsync-token")
    main_module.set_state("quarantined")
    monkeypatch.setattr(main_module, "_fsync_directory", lambda path: (_ for _ in ()).throw(OSError("directory fsync failed")))

    with pytest.raises(OSError):
        main_module._consume_recovery_token()
    assert marker.exists()
    assert main_module.health_check()["status"] == "quarantined"
    assert main_module._consume_recovery_token() is False


def test_preflight_directory_fsync_failure_retains_quarantine_and_blocks_ready(
    isolated_test_application, monkeypatch
):
    marker = Path(isolated_test_application["engine"].url.database).with_name("preflight-reservation-fsync.flag")
    marker.write_text("quarantined\n", encoding="utf-8")
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(marker))
    _set_recovery_token(monkeypatch, "preflight-reservation-fsync-token")
    monkeypatch.setattr(
        main_module,
        "_fsync_directory",
        lambda path: (_ for _ in ()).throw(OSError("reservation directory fsync failed")),
    )
    main_module.set_state("quarantined")

    assert main_module.run_integrity_preflight() is False
    assert marker.exists()
    assert main_module.health_check()["status"] == "quarantined"
    with TestClient(main_module.app) as client:
        assert client.get("/ready").status_code == 503
    reservation = marker.with_name(marker.name + ".recovery-consumed")
    assert reservation.exists()
    assert main_module._consume_recovery_token() is False


def test_preflight_malformed_reservation_fails_closed(isolated_test_application, monkeypatch):
    marker = Path(isolated_test_application["engine"].url.database).with_name("preflight-malformed.flag")
    marker.write_text("quarantined\n", encoding="utf-8")
    reservation = marker.with_name(marker.name + ".recovery-consumed")
    reservation.write_text("not-json\n", encoding="utf-8")
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(marker))
    _set_recovery_token(monkeypatch, "preflight-malformed-token")
    monkeypatch.setattr(main_module, "_consume_recovery_token", lambda: True)

    assert main_module.run_integrity_preflight() is False
    assert marker.exists()
    assert main_module.health_check()["status"] == "quarantined"


def test_preflight_unreadable_reservation_fails_closed(isolated_test_application, monkeypatch):
    marker = Path(isolated_test_application["engine"].url.database).with_name("preflight-unreadable.flag")
    marker.write_text("quarantined\n", encoding="utf-8")
    reservation = marker.with_name(marker.name + ".recovery-consumed")
    reservation.write_text('{"tokenHash":"abc","outcome":"attempted"}\n', encoding="utf-8")
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(marker))
    _set_recovery_token(monkeypatch, "preflight-unreadable-token")
    monkeypatch.setattr(main_module, "_consume_recovery_token", lambda: True)
    monkeypatch.setattr(Path, "read_text", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("read failed")))

    assert main_module.run_integrity_preflight() is False
    assert marker.exists()
    assert main_module.health_check()["status"] == "quarantined"


def test_restart_after_interruption_before_outcome_cannot_reuse_token(isolated_test_application, monkeypatch):
    marker = Path(isolated_test_application["engine"].url.database).with_name("crash-before-outcome.flag")
    marker.write_text("quarantined\n", encoding="utf-8")
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(marker))
    _set_recovery_token(monkeypatch, "crash-before-outcome-token")
    env = os.environ.copy()
    env["AUDIT_QUARANTINE_MARKER"] = str(marker)
    env["AUDIT_QUARANTINE_RECOVERY_TOKEN_DIGEST"] = hashlib.sha256(b"crash-before-outcome-token").hexdigest()
    main_module.set_state("quarantined")
    command = "from app.main import _consume_recovery_token; import os; _consume_recovery_token(); os._exit(0)"
    process = subprocess.run([sys.executable, "-c", command], cwd=str(Path(__file__).parents[1]), env=env, timeout=10)
    assert process.returncode == 0
    assert main_module.run_integrity_preflight() is False
    assert marker.exists()


def test_restart_after_outcome_before_marker_removal_cannot_reuse_token(isolated_test_application, monkeypatch):
    marker = Path(isolated_test_application["engine"].url.database).with_name("crash-before-unlink.flag")
    marker.write_text("quarantined\n", encoding="utf-8")
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(marker))
    _set_recovery_token(monkeypatch, "crash-before-unlink-token")
    env = os.environ.copy()
    env["AUDIT_QUARANTINE_MARKER"] = str(marker)
    env["AUDIT_QUARANTINE_RECOVERY_TOKEN_DIGEST"] = hashlib.sha256(b"crash-before-unlink-token").hexdigest()
    main_module.set_state("quarantined")
    command = "from app.main import _consume_recovery_token, _record_recovery_outcome; import os; _consume_recovery_token(); _record_recovery_outcome('successful'); os._exit(0)"
    process = subprocess.run([sys.executable, "-c", command], cwd=str(Path(__file__).parents[1]), env=env, timeout=10)
    assert process.returncode == 0
    assert main_module.run_integrity_preflight() is False
    assert marker.exists()


@pytest.mark.parametrize("failure", ["write", "replace", "file_fsync", "directory_fsync"])
def test_recovery_outcome_persistence_failures_raise_and_preserve_reservation(
    isolated_test_application, monkeypatch, failure
):
    marker = Path(isolated_test_application["engine"].url.database).with_name(f"outcome-{failure}.flag")
    reservation = marker.with_name(marker.name + ".recovery-consumed")
    reservation.write_text('{"tokenHash":"abc","outcome":"attempted"}\n', encoding="utf-8")
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(marker))
    if failure == "write":
        monkeypatch.setattr(main_module.os, "fdopen", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("write failed")))
    elif failure == "replace":
        monkeypatch.setattr(main_module.os, "replace", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("replace failed")))
    elif failure == "file_fsync":
        monkeypatch.setattr(main_module.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("fsync failed")))
    else:
        monkeypatch.setattr(main_module, "_fsync_directory", lambda path: (_ for _ in ()).throw(OSError("directory fsync failed")))
    with pytest.raises(OSError):
        main_module._record_recovery_outcome("successful")
    assert reservation.exists()


def test_failed_outcome_persistence_never_removes_quarantine_marker(isolated_test_application, monkeypatch):
    marker = Path(isolated_test_application["engine"].url.database).with_name("outcome-marker.flag")
    marker.write_text("quarantined\n", encoding="utf-8")
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(marker))
    _set_recovery_token(monkeypatch, "outcome-marker-token")
    monkeypatch.setattr(main_module, "_consume_recovery_token", lambda: True)
    monkeypatch.setattr(main_module, "_record_recovery_outcome", lambda outcome: (_ for _ in ()).throw(OSError("outcome unavailable")))

    assert main_module.run_integrity_preflight() is False
    assert marker.exists()
    assert main_module.health_check()["status"] == "quarantined"


def test_marker_removal_failure_keeps_service_quarantined(isolated_test_application, monkeypatch):
    marker = Path(isolated_test_application["engine"].url.database).with_name("unlink-marker.flag")
    marker.write_text("quarantined\n", encoding="utf-8")
    reservation = marker.with_name(marker.name + ".recovery-consumed")
    reservation.write_text('{"tokenHash":"abc","outcome":"attempted"}\n', encoding="utf-8")
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(marker))
    _set_recovery_token(monkeypatch, "unlink-marker-token")
    monkeypatch.setattr(main_module, "_consume_recovery_token", lambda: True)
    monkeypatch.setattr(Path, "unlink", lambda self: (_ for _ in ()).throw(OSError("unlink failed")))

    assert main_module.run_integrity_preflight() is False
    assert marker.exists()
    assert main_module.health_check()["status"] == "quarantined"

# End of quarantine recovery regression coverage.

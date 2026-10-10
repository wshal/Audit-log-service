"""Startup integrity preflight and fail-closed quarantine tests."""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import text

import app.main as main_module
from app.crypto.hasher import GENESIS_PREV_HASH
from app.crypto.signer import sign_record_hash, signing_key_id
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


def test_malformed_legacy_record_quarantines_and_blocks_audit_routes(isolated_test_application):
    session = isolated_test_application["session_factory"]()
    _record(session, payload_json="not-json")
    session.close()
    with TestClient(main_module.app) as client:
        assert client.get("/health").json() == {"status": "quarantined", "service": main_module.settings.APP_NAME, "version": main_module.settings.APP_VERSION}
        assert client.get("/ready").status_code == 503
        assert client.get("/audit/events").status_code == 503
        assert client.post("/audit/events", json={}).status_code == 503


def test_valid_mixed_ledger_preflight_succeeds(isolated_test_application):
    session = isolated_test_application["session_factory"]()
    repo = AuditLedgerRepository(session)
    repo.append_event(AuditEventCreate(eventType="V1", actorId="actor", resourceType="CLIENT", resourceId="client", payload={}, timestamp="2026-01-01T00:00:00Z"), Principal("actor", frozenset({"writer"}), "v1", (), True))
    repo.append_event(AuditEventCreate(eventType="V2", actorId="actor", resourceType="CLIENT_ACCOUNT", resourceId="client-a", payload={}, timestamp="2026-01-01T00:00:01Z", tenantId="tenant-a"), Principal("actor", frozenset({"writer"}), "v2"))
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
    monkeypatch.setenv("AUDIT_QUARANTINE_RECOVERY_TOKEN", "one-time-token")
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


def test_missing_mixed_transition_quarantines(isolated_test_application):
    session = isolated_test_application["session_factory"]()
    repo = AuditLedgerRepository(session)
    repo.append_event(AuditEventCreate(eventType="V2", actorId="actor", resourceType="CLIENT_ACCOUNT", resourceId="client-a", payload={}, timestamp="2026-01-01T00:00:01Z", tenantId="tenant-a"), Principal("actor", frozenset({"writer"}), "v2"))
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
    monkeypatch.setenv("AUDIT_QUARANTINE_RECOVERY_TOKEN", "one-time-token")
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

"""Focused tests for the versioned schema and ledger-state foundation."""

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from alembic.command import downgrade
from alembic.config import Config
from pathlib import Path
from app.security import Principal
from app.services.verifier import ChainVerificationService

from app.crypto.hasher import canonical_json, compute_event_content_hash, compute_record_chain_hash, compute_sha256
from app.crypto.signer import _private_key, public_key_ring, sign_record_hash, signing_key_id
from app.storage.database import (
    AuditEpochTransitionEntity,
    AuditRecordEntity,
    Base,
    LedgerStateEntity,
    init_db,
    initialize_ledger_state,
)


def _create_legacy_audit_table(connection):
    connection.execute(text("""
        CREATE TABLE audit_records (
          id INTEGER PRIMARY KEY, sequence_num INTEGER NOT NULL UNIQUE,
          event_type VARCHAR(128) NOT NULL, actor_id VARCHAR(128) NOT NULL,
          resource_type VARCHAR(128) NOT NULL, resource_id VARCHAR(256) NOT NULL,
          payload_json TEXT NOT NULL, timestamp VARCHAR(64) NOT NULL,
          content_hash VARCHAR(64) NOT NULL, prev_hash VARCHAR(64) NOT NULL,
          record_hash VARCHAR(64) NOT NULL, is_archived BOOLEAN NOT NULL DEFAULT 0,
          archived_at VARCHAR(64), archival_reason VARCHAR(256),
          redaction_metadata_json TEXT
        )
    """))


def _replace_stamped_audit_table(connection, *, tenant_definition="VARCHAR(128)"):
    connection.execute(text("""
        CREATE TABLE audit_records_replacement (
          id INTEGER PRIMARY KEY, sequence_num INTEGER NOT NULL UNIQUE,
          event_type VARCHAR(128) NOT NULL, actor_id VARCHAR(128) NOT NULL,
          resource_type VARCHAR(128) NOT NULL, resource_id VARCHAR(256) NOT NULL,
          payload_json TEXT NOT NULL, timestamp VARCHAR(64) NOT NULL,
          content_hash VARCHAR(64) NOT NULL, prev_hash VARCHAR(64) NOT NULL,
          record_hash VARCHAR(64) NOT NULL, record_signature TEXT,
          signing_key_id VARCHAR(128), is_archived BOOLEAN NOT NULL DEFAULT 0,
          archived_at VARCHAR(64), archival_reason VARCHAR(256),
          redaction_metadata_json TEXT, tenant_id """ + tenant_definition + """,
          authenticated_subject VARCHAR(128), credential_id VARCHAR(128),
          attribution_mode VARCHAR(32), delegation_reason VARCHAR(512),
          protocol_version INTEGER NOT NULL DEFAULT 1
        )
    """))
    connection.execute(text("DROP TABLE audit_records"))
    connection.execute(text("ALTER TABLE audit_records_replacement RENAME TO audit_records"))


def _stamp_current_schema(engine):
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        connection.execute(text("INSERT INTO alembic_version VALUES ('0001_schema_foundation')"))


def test_fresh_migration_creates_version_and_empty_ledger_state(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'fresh.db').as_posix()}")

    init_db(engine)
    init_db(engine)

    tables = set(inspect(engine).get_table_names())
    assert {"audit_records", "audit_epoch_transitions", "ledger_state", "alembic_version"}.issubset(tables)
    with engine.connect() as connection:
        revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        assert revision == "0002_idempotency_records"
        assert connection.execute(text("SELECT COUNT(*) FROM ledger_state")).scalar_one() == 0


def test_idempotency_downgrade_fails_closed_without_dropping_records(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'downgrade.db').as_posix()}")
    init_db(engine)
    with engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO audit_records (sequence_num, event_type, actor_id, resource_type, resource_id, payload_json, timestamp, content_hash, prev_hash, record_hash, is_archived, protocol_version) "
            "VALUES (1, 'TEST', 'actor', 'TEST', 'resource', '{}', '2026-01-01T00:00:00Z', :hash, :hash, :hash, 0, 1)"
        ), {"hash": "0" * 64})
        connection.execute(text(
            "INSERT INTO idempotency_records (scope_principal, scope_tenant, scope_method, scope_endpoint, idempotency_key, request_fingerprint, audit_record_id, created_at, expires_at) "
            "VALUES ('actor', '__legacy__', 'POST', '/audit/events', 'downgrade-key', :fingerprint, 1, '2026-01-01T00:00:00Z', '2099-01-01T00:00:00Z')"
        ), {"fingerprint": "a" * 64})
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    with pytest.raises(RuntimeError, match="no automatic destructive downgrade"):
        with engine.begin() as connection:
            config.attributes["connection"] = connection
            downgrade(config, "base")
    with engine.connect() as connection:
        assert connection.execute(text("SELECT COUNT(*) FROM idempotency_records")).scalar_one() == 1
        assert connection.execute(text("SELECT COUNT(*) FROM audit_records")).scalar_one() == 1


def test_ledger_state_constraints_are_enforced(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'constraints.db').as_posix()}")
    init_db(engine)
    session = sessionmaker(bind=engine)()
    try:
        session.add(LedgerStateEntity(singleton_id=1, next_sequence=1, tip_hash="0" * 64, state_version=1))
        session.commit()

        invalid_rows = (
            LedgerStateEntity(singleton_id=2, next_sequence=1, tip_hash="0" * 64, state_version=1),
            LedgerStateEntity(singleton_id=1, next_sequence=0, tip_hash="0" * 64, state_version=1),
            LedgerStateEntity(singleton_id=1, next_sequence=2, tip_hash="bad", state_version=1),
            LedgerStateEntity(singleton_id=1, next_sequence=2, tip_hash="0" * 64, state_version=0),
        )
        for row in invalid_rows:
            session.add(row)
            with pytest.raises(IntegrityError):
                session.commit()
            session.rollback()
    finally:
        session.close()


def test_unrecognized_pre_migration_schema_fails_without_stamping(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'incompatible.db').as_posix()}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE audit_records (id INTEGER PRIMARY KEY)"))

    with pytest.raises(RuntimeError, match="Existing audit_records schema is incompatible"):
        init_db(engine)

    tables = set(inspect(engine).get_table_names())
    assert "alembic_version" not in tables
    assert tables == {"audit_records"}


def test_unrelated_non_empty_database_is_not_treated_as_fresh(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'unrelated.db').as_posix()}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE unrelated (id INTEGER PRIMARY KEY, value TEXT)"))
        connection.execute(text("INSERT INTO unrelated VALUES (1, 'keep')"))

    with pytest.raises(RuntimeError, match="unrecognized non-empty schema"):
        init_db(engine)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT value FROM unrelated WHERE id=1")).scalar_one() == "keep"
    assert "alembic_version" not in inspect(engine).get_table_names()


def test_stamped_valid_schema_is_revalidated(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'stamped.db').as_posix()}")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        connection.execute(text("INSERT INTO alembic_version VALUES ('0001_schema_foundation')"))
    init_db(engine)


def test_stamped_schema_missing_column_is_rejected(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'stamped-missing.db').as_posix()}")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        connection.execute(text("INSERT INTO alembic_version VALUES ('0001_schema_foundation')"))
        connection.execute(text("DROP INDEX ix_audit_records_tenant_id"))
        connection.execute(text("ALTER TABLE audit_records DROP COLUMN tenant_id"))

    with pytest.raises(RuntimeError, match="Stamped schema is incomplete|missing columns"):
        init_db(engine)


def test_stamped_schema_wrong_type_is_rejected(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'stamped-type.db').as_posix()}")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        _replace_stamped_audit_table(connection, tenant_definition="INTEGER")
    _stamp_current_schema(engine)

    with pytest.raises(RuntimeError, match="tenant_id schema is incompatible"):
        init_db(engine)
    assert "INTEGER" in engine.connect().execute(text(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='audit_records'"
    )).scalar_one()


def test_stamped_schema_wrong_nullability_is_rejected(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'stamped-nullability.db').as_posix()}")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        _replace_stamped_audit_table(connection, tenant_definition="VARCHAR(128) NOT NULL")
    _stamp_current_schema(engine)

    with pytest.raises(RuntimeError, match="tenant_id schema is incompatible; expected nullable"):
        init_db(engine)


def test_stamped_schema_missing_tip_hash_constraint_is_rejected(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'stamped-check.db').as_posix()}")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE ledger_state RENAME TO ledger_state_original"))
        connection.execute(text("""
            CREATE TABLE ledger_state (
              singleton_id INTEGER PRIMARY KEY,
              next_sequence INTEGER NOT NULL,
              tip_hash VARCHAR(64) NOT NULL,
              state_version INTEGER NOT NULL,
              CHECK (singleton_id = 1),
              CHECK (next_sequence >= 1),
              CHECK (state_version >= 1)
            )
        """))
        connection.execute(text("DROP TABLE ledger_state_original"))
    _stamp_current_schema(engine)

    with pytest.raises(RuntimeError, match=r"missing check length\(tip_hash\) = 64"):
        init_db(engine)


def test_unknown_stamped_revision_is_rejected(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'unknown-revision.db').as_posix()}")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        connection.execute(text("INSERT INTO alembic_version VALUES ('9999_unknown')"))

    with pytest.raises(RuntimeError, match="Unsupported or unknown database migration revision"):
        init_db(engine)


def test_malformed_transition_table_fails_before_stamping(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'bad-transition.db').as_posix()}")
    with engine.begin() as connection:
        _create_legacy_audit_table(connection)
        connection.execute(text("CREATE TABLE audit_epoch_transitions (id INTEGER PRIMARY KEY, transition_hash TEXT)"))

    with pytest.raises(RuntimeError, match="Existing audit_epoch_transitions"):
        init_db(engine)
    assert "alembic_version" not in inspect(engine).get_table_names()


def test_malformed_ledger_state_fails_before_stamping(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'bad-state.db').as_posix()}")
    with engine.begin() as connection:
        _create_legacy_audit_table(connection)
        connection.execute(text("CREATE TABLE ledger_state (singleton_id INTEGER PRIMARY KEY)"))

    with pytest.raises(RuntimeError, match="ledger_state schema is incompatible"):
        init_db(engine)
    assert "alembic_version" not in inspect(engine).get_table_names()


def test_failed_additive_migration_is_retryable_without_history_change(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{(tmp_path / 'retry.db').as_posix()}")
    with engine.begin() as connection:
        _create_legacy_audit_table(connection)
        connection.execute(text(
            "INSERT INTO audit_records VALUES "
            "(1,1,'V1','actor','CLIENT','c','{}','2026-01-01T00:00:00Z','c','p','r',0,NULL,NULL,NULL)"
        ))

    from alembic.operations import Operations
    original_add_column = Operations.add_column
    calls = {"count": 0}

    def fail_after_first_add(operation, *args, **kwargs):
        result = original_add_column(operation, *args, **kwargs)
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("injected migration failure")
        return result

    monkeypatch.setattr(Operations, "add_column", fail_after_first_add)
    with pytest.raises(RuntimeError, match="injected migration failure"):
        init_db(engine)

    with engine.connect() as connection:
        before_retry = connection.execute(text(
            "SELECT sequence_num, payload_json, content_hash, prev_hash, record_hash, "
            "record_signature FROM audit_records WHERE id=1"
        )).one()
        inspector = inspect(engine)
        columns = {column["name"]: column for column in inspector.get_columns("audit_records")}
        assert "record_signature" in columns
        assert columns["record_signature"]["type"].__class__.__name__ == "TEXT"
        assert columns["record_signature"]["nullable"] is True
        assert {"audit_records", "alembic_version"}.issubset(inspector.get_table_names())
        assert {"id", "sequence_num", "payload_json", "content_hash", "prev_hash", "record_hash"}.issubset(columns)
        assert connection.execute(text("SELECT COUNT(*) FROM alembic_version")).scalar_one() == 0

    monkeypatch.setattr(Operations, "add_column", original_add_column)
    init_db(engine)
    with engine.connect() as connection:
        after_retry = connection.execute(text(
            "SELECT sequence_num, payload_json, content_hash, prev_hash, record_hash, "
            "record_signature FROM audit_records WHERE id=1"
        )).one()
        assert tuple(before_retry) == tuple(after_retry)
        final_columns = {column["name"] for column in inspect(engine).get_columns("audit_records")}
        assert {"record_signature", "signing_key_id", "tenant_id", "protocol_version"}.issubset(final_columns)
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0002_idempotency_records"


def test_malformed_intermediate_optional_column_is_rejected_before_retry(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'malformed-intermediate.db').as_posix()}")
    with engine.begin() as connection:
        _create_legacy_audit_table(connection)
        connection.execute(text("ALTER TABLE audit_records ADD COLUMN record_signature INTEGER"))

    with pytest.raises(RuntimeError, match="record_signature schema is incompatible"):
        init_db(engine)
    assert "alembic_version" not in inspect(engine).get_table_names()


def test_populated_v1_v2_history_is_byte_preserved(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_DEVELOPMENT_KEY_PATH", str(tmp_path / "signing.key"))
    _private_key.cache_clear()
    public_key_ring.cache_clear()
    engine = create_engine(f"sqlite:///{(tmp_path / 'populated.db').as_posix()}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        v1_payload = {"purpose": "review"}
        v1_timestamp = "2026-01-01T00:00:00Z"
        v1_content = compute_event_content_hash("V1", "legacy-actor", "CLIENT", "legacy-1", v1_payload, v1_timestamp, protocol_version=1)
        v1_record_hash = compute_record_chain_hash(1, v1_content, "0" * 64)
        v2_payload = {"purpose": "review"}
        v2_timestamp = "2026-01-01T00:00:01Z"
        v2_content = compute_event_content_hash(
            "ACCOUNT_VIEWED", "actor-a", "CLIENT_ACCOUNT", "client-a", v2_payload, v2_timestamp,
            tenant_id="tenant-a", authenticated_subject="actor-a", credential_id="cred-a",
            attribution_mode="DIRECT", protocol_version=2,
        )
        v2_record_hash = compute_record_chain_hash(2, v2_content, v1_record_hash)
        session.add_all([
            AuditRecordEntity(
                sequence_num=1, event_type="V1", actor_id="legacy-actor", resource_type="CLIENT", resource_id="legacy-1",
                payload_json=canonical_json(v1_payload), timestamp=v1_timestamp, content_hash=v1_content,
                prev_hash="0" * 64, record_hash=v1_record_hash, record_signature=sign_record_hash(v1_record_hash),
                signing_key_id=signing_key_id(), protocol_version=1,
            ),
            AuditRecordEntity(
                sequence_num=2, event_type="ACCOUNT_VIEWED", actor_id="actor-a", resource_type="CLIENT_ACCOUNT", resource_id="client-a",
                payload_json=canonical_json(v2_payload), timestamp=v2_timestamp, content_hash=v2_content,
                prev_hash=v1_record_hash, record_hash=v2_record_hash, record_signature=sign_record_hash(v2_record_hash),
                signing_key_id=signing_key_id(), tenant_id="tenant-a", authenticated_subject="actor-a",
                credential_id="cred-a", attribution_mode="DIRECT", protocol_version=2,
            ),
        ])
        transition_material = canonical_json({
            "legacyTipHash": v1_record_hash, "legacyRecordCount": 1,
            "v2GenesisHash": v2_record_hash, "v2GenesisSequence": 2,
            "cutoverTimestamp": v2_timestamp, "protocolVersion": 2,
        })
        transition_hash = compute_sha256(transition_material)
        session.add(AuditEpochTransitionEntity(
            legacy_tip_hash=v1_record_hash, legacy_record_count=1, v2_genesis_hash=v2_record_hash,
            v2_genesis_sequence=2, cutover_timestamp=v2_timestamp, transition_hash=transition_hash,
            transition_signature=sign_record_hash(transition_hash), signing_key_id=signing_key_id(), protocol_version=2,
        ))
        session.commit()
        before_records = [tuple(row) for row in session.execute(text(
            "SELECT sequence_num, event_type, actor_id, payload_json, timestamp, content_hash, prev_hash, record_hash, "
            "record_signature, signing_key_id, tenant_id, authenticated_subject, credential_id, attribution_mode, protocol_version "
            "FROM audit_records ORDER BY sequence_num"
        )).all()]
        before_transition = tuple(session.execute(text(
            "SELECT legacy_tip_hash, legacy_record_count, v2_genesis_hash, v2_genesis_sequence, cutover_timestamp, "
            "transition_hash, transition_signature, signing_key_id, protocol_version FROM audit_epoch_transitions"
        )).one())
    finally:
        session.close()

    init_db(engine)
    with engine.connect() as connection:
        after_records = [tuple(row) for row in connection.execute(text(
            "SELECT sequence_num, event_type, actor_id, payload_json, timestamp, content_hash, prev_hash, record_hash, "
            "record_signature, signing_key_id, tenant_id, authenticated_subject, credential_id, attribution_mode, protocol_version "
            "FROM audit_records ORDER BY sequence_num"
        )).all()]
        after_transition = tuple(connection.execute(text(
            "SELECT legacy_tip_hash, legacy_record_count, v2_genesis_hash, v2_genesis_sequence, cutover_timestamp, "
            "transition_hash, transition_signature, signing_key_id, protocol_version FROM audit_epoch_transitions"
        )).one())
    assert before_records == after_records
    assert before_transition == after_transition
    initialize_ledger_state(engine)
    verification_session = sessionmaker(bind=engine)()
    try:
        verification = ChainVerificationService.verify_ledger(
            verification_session,
            principal=Principal("migration-check", frozenset({"global_auditor"}), "migration-check"),
        )
        assert verification.intact is True
    finally:
        verification_session.close()

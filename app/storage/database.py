"""
Database models and connection engine for the append-only audit ledger.
"""

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


_BASE_AUDIT_COLUMNS = {
    "id", "sequence_num", "event_type", "actor_id", "resource_type", "resource_id",
    "payload_json", "timestamp", "content_hash", "prev_hash", "record_hash",
    "is_archived", "archived_at", "archival_reason", "redaction_metadata_json",
}
_BASE_TRANSITION_COLUMNS = {
    "id", "legacy_tip_hash", "legacy_record_count", "v2_genesis_hash",
    "transition_hash", "transition_signature", "signing_key_id", "protocol_version",
}
_LEDGER_STATE_COLUMNS = {"singleton_id", "next_sequence", "tip_hash", "state_version"}

_LEGACY_COLUMN_SPECS = {
    "id": (Integer, False),
    "sequence_num": (Integer, False),
    "event_type": (String, False),
    "actor_id": (String, False),
    "resource_type": (String, False),
    "resource_id": (String, False),
    "payload_json": (Text, False),
    "timestamp": (String, False),
    "content_hash": (String, False),
    "prev_hash": (String, False),
    "record_hash": (String, False),
    "is_archived": (Boolean, False),
    "archived_at": (String, True),
    "archival_reason": (String, True),
    "redaction_metadata_json": (Text, True),
}
_OPTIONAL_AUDIT_COLUMN_SPECS = {
    "record_signature": (Text, True),
    "signing_key_id": (String, True),
    "tenant_id": (String, True),
    "authenticated_subject": (String, True),
    "credential_id": (String, True),
    "attribution_mode": (String, True),
    "delegation_reason": (String, True),
    "protocol_version": (Integer, False),
}
_TRANSITION_COLUMN_SPECS = {
    "id": (Integer, False),
    "legacy_tip_hash": (String, False),
    "legacy_record_count": (Integer, False),
    "v2_genesis_hash": (String, False),
    "v2_genesis_sequence": (Integer, False),
    "cutover_timestamp": (String, False),
    "transition_hash": (String, False),
    "transition_signature": (Text, False),
    "signing_key_id": (String, False),
    "protocol_version": (Integer, False),
}
_LEDGER_STATE_COLUMN_SPECS = {
    "singleton_id": (Integer, False),
    "next_sequence": (Integer, False),
    "tip_hash": (String, False),
    "state_version": (Integer, False),
}


def _type_family(type_object):
    """Return a portable SQLAlchemy type family for SQLite/PostgreSQL checks."""
    if isinstance(type_object, Boolean):
        return Boolean
    if isinstance(type_object, Integer):
        return Integer
    if isinstance(type_object, Text):
        return Text
    if isinstance(type_object, String):
        return String
    return type(type_object)


def _validate_column_specs(inspector, table_name: str, specs: dict) -> None:
    columns = {column["name"]: column for column in inspector.get_columns(table_name)}
    missing = set(specs) - set(columns)
    if missing:
        raise RuntimeError(
            f"Existing {table_name} schema is incompatible; missing columns: {', '.join(sorted(missing))}"
        )
    for name, (expected_type, expected_nullable) in specs.items():
        column = columns[name]
        actual_family = _type_family(column["type"])
        if actual_family is not expected_type:
            raise RuntimeError(
                f"Existing {table_name}.{name} schema is incompatible; expected {expected_type.__name__}"
            )
        # SQLite reflection reports INTEGER PRIMARY KEY columns as nullable even
        # though the primary-key constraint makes them non-null in practice.
        reflected_nullable = bool(column.get("nullable"))
        primary_key_name = name in {"id", "singleton_id"}
        if not primary_key_name and reflected_nullable != expected_nullable:
            state = "nullable" if expected_nullable else "non-nullable"
            raise RuntimeError(f"Existing {table_name}.{name} schema is incompatible; expected {state}")


def _validate_default(inspector, table_name: str, column_name: str, allowed: set[str]) -> None:
    column = next(column for column in inspector.get_columns(table_name) if column["name"] == column_name)
    default = column.get("default")
    normalized = str(default).strip().strip("'").lower() if default is not None else "none"
    if normalized not in allowed:
        raise RuntimeError(
            f"Existing {table_name}.{column_name} schema is incompatible; unexpected default {default!r}"
        )


def _has_unique_column(inspector, table_name: str, column_name: str) -> bool:
    if any(set(item.get("column_names", ())) == {column_name}
           for item in inspector.get_unique_constraints(table_name)):
        return True
    return any(index.get("unique") and set(index.get("column_names", ())) == {column_name}
               for index in inspector.get_indexes(table_name))


def _validate_table_shape(inspector, table_name: str, required_columns: set[str], *, unique_column: str) -> None:
    actual = {column["name"] for column in inspector.get_columns(table_name)}
    missing = required_columns - actual
    if missing:
        raise RuntimeError(
            f"Existing {table_name} schema is incompatible; missing columns: {', '.join(sorted(missing))}"
        )
    primary_key = inspector.get_pk_constraint(table_name).get("constrained_columns", [])
    if primary_key != ["id"]:
        raise RuntimeError(f"Existing {table_name} schema is incompatible; expected primary key id")
    if not _has_unique_column(inspector, table_name, unique_column):
        raise RuntimeError(f"Existing {table_name} schema is incompatible; {unique_column} must be unique")


def _validate_ledger_state_checks(inspector, *, stamped: bool) -> None:
    """Validate named ledger invariants across dialect-specific reflection text."""
    prefix = "Stamped " if stamped else "Existing "
    checks = [str(item.get("sqltext") or "").lower() for item in inspector.get_check_constraints("ledger_state")]
    normalized = [re.sub(r"[\s\"'`()\[\]]", "", value) for value in checks]
    requirements = (
        ("singleton_id = 1", lambda value: "singleton_id=1" in value),
        ("next_sequence >= 1", lambda value: "next_sequence" in value and ">=1" in value),
        ("state_version >= 1", lambda value: "state_version" in value and ">=1" in value),
        (
            "length(tip_hash) = 64",
            lambda value: "tip_hash" in value
            and "64" in value
            and any(function in value for function in ("length", "char_length", "octet_length")),
        ),
    )
    for fragment, matches in requirements:
        if not any(matches(value) for value in normalized):
            raise RuntimeError(f"{prefix}ledger_state schema is incompatible; missing check {fragment}")


def validate_pre_migration_schema(engine) -> None:
    """Reject unknown pre-Alembic schemas before migration state is created."""
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    if "audit_records" not in tables:
        if tables:
            raise RuntimeError("Existing database has unrecognized non-empty schema; refusing fresh initialization")
        return

    _validate_column_specs(inspector, "audit_records", _LEGACY_COLUMN_SPECS)
    _validate_default(inspector, "audit_records", "is_archived", {"0", "false", "false::boolean", "none"})
    _validate_table_shape(inspector, "audit_records", _BASE_AUDIT_COLUMNS, unique_column="sequence_num")
    present_optional = {
        name: spec for name, spec in _OPTIONAL_AUDIT_COLUMN_SPECS.items()
        if name in {column["name"] for column in inspector.get_columns("audit_records")}
    }
    if present_optional:
        _validate_column_specs(inspector, "audit_records", present_optional)
        if "protocol_version" in present_optional:
            _validate_default(inspector, "audit_records", "protocol_version", {"1", "1::integer", "none"})
    if "audit_epoch_transitions" in tables:
        transition_columns = {column["name"] for column in inspector.get_columns("audit_epoch_transitions")}
        _validate_column_specs(
            inspector,
            "audit_epoch_transitions",
            {name: spec for name, spec in _TRANSITION_COLUMN_SPECS.items() if name in transition_columns},
        )
        _validate_table_shape(
            inspector,
            "audit_epoch_transitions",
            _BASE_TRANSITION_COLUMNS,
            unique_column="transition_hash",
        )
    if "ledger_state" in tables:
        _validate_column_specs(inspector, "ledger_state", _LEDGER_STATE_COLUMN_SPECS)
        primary_key = inspector.get_pk_constraint("ledger_state").get("constrained_columns", [])
        if primary_key != ["singleton_id"]:
            raise RuntimeError("Existing ledger_state schema is incompatible; expected primary key singleton_id")
        _validate_ledger_state_checks(inspector, stamped=False)


def validate_current_schema(engine, revision: str) -> None:
    """Validate a stamped revision before application code relies on it."""
    if revision != "0001_schema_foundation":
        raise RuntimeError(f"Unsupported or unknown database migration revision: {revision}")
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    required_tables = {"audit_records", "audit_epoch_transitions", "ledger_state", "alembic_version"}
    missing_tables = required_tables - tables
    if missing_tables:
        raise RuntimeError("Stamped schema is incomplete; missing tables: " + ", ".join(sorted(missing_tables)))
    _validate_column_specs(inspector, "audit_records", {**_LEGACY_COLUMN_SPECS, **_OPTIONAL_AUDIT_COLUMN_SPECS})
    _validate_default(inspector, "audit_records", "is_archived", {"0", "false", "false::boolean", "none"})
    _validate_default(inspector, "audit_records", "protocol_version", {"1", "1::integer", "none"})
    _validate_table_shape(inspector, "audit_records", set(_LEGACY_COLUMN_SPECS) | set(_OPTIONAL_AUDIT_COLUMN_SPECS), unique_column="sequence_num")
    _validate_column_specs(inspector, "audit_epoch_transitions", _TRANSITION_COLUMN_SPECS)
    _validate_table_shape(inspector, "audit_epoch_transitions", set(_TRANSITION_COLUMN_SPECS), unique_column="transition_hash")
    _validate_column_specs(inspector, "ledger_state", _LEDGER_STATE_COLUMN_SPECS)
    _validate_ledger_state_checks(inspector, stamped=True)


class AuditRecordEntity(Base):
    """
    Relational representation of an immutable audit record block.
    Enforces indexing across queried fields (actorId, resourceType, resourceId, eventType, timestamp).
    """
    __tablename__ = "audit_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sequence_num = Column(Integer, unique=True, nullable=False, index=True)
    event_type = Column(String(128), nullable=False, index=True)
    actor_id = Column(String(128), nullable=False, index=True)
    resource_type = Column(String(128), nullable=False, index=True)
    resource_id = Column(String(256), nullable=False, index=True)
    payload_json = Column(Text, nullable=False)
    timestamp = Column(String(64), nullable=False, index=True)
    
    # Cryptographic integrity fields
    content_hash = Column(String(64), nullable=False)
    prev_hash = Column(String(64), nullable=False)
    record_hash = Column(String(64), nullable=False)
    record_signature = Column(Text, nullable=True)
    signing_key_id = Column(String(128), nullable=True)

    # Lifecycle & Redaction support (Scenario B)
    is_archived = Column(Boolean, default=False, nullable=False)
    archived_at = Column(String(64), nullable=True)
    archival_reason = Column(String(256), nullable=True)
    
    # Structured redaction metadata (stores commitments/salts for masked fields)
    redaction_metadata_json = Column(Text, nullable=True)
    # Versioned tenant-bound epoch (nullable for frozen V1 records).
    tenant_id = Column(String(128), nullable=True, index=True)
    authenticated_subject = Column(String(128), nullable=True)
    credential_id = Column(String(128), nullable=True)
    attribution_mode = Column(String(32), nullable=True)
    delegation_reason = Column(String(512), nullable=True)
    protocol_version = Column(Integer, nullable=False, default=1)

    __table_args__ = (
        Index("idx_audit_resource", "resource_type", "resource_id"),
        Index("idx_audit_actor_time", "actor_id", "timestamp"),
        Index("idx_audit_event_time", "event_type", "timestamp"),
    )

    def to_read_model(self) -> Dict[str, Any]:
        """Convert database entity to schema dictionary."""
        return {
            "id": self.id,
            "sequenceNum": self.sequence_num,
            "eventType": self.event_type,
            "actorId": self.actor_id,
            "resourceType": self.resource_type,
            "resourceId": self.resource_id,
            "payload": json.loads(self.payload_json),
            "timestamp": self.timestamp,
            "contentHash": self.content_hash,
            "prevHash": self.prev_hash,
            "recordHash": self.record_hash,
            "recordSignature": self.record_signature,
            "signingKeyId": self.signing_key_id,
            "isArchived": self.is_archived,
            "archivedAt": self.archived_at,
            "redactionMetadata": json.loads(self.redaction_metadata_json) if self.redaction_metadata_json else None,
            "tenantId": self.tenant_id,
            "authenticatedSubject": self.authenticated_subject,
            "credentialId": self.credential_id,
            "attributionMode": self.attribution_mode,
            "protocolVersion": self.protocol_version or 1,
        }


class AuditEpochTransitionEntity(Base):
    """Signed, immutable evidence for the V1 to V2 protocol cutover."""
    __tablename__ = "audit_epoch_transitions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    legacy_tip_hash = Column(String(64), nullable=False)
    legacy_record_count = Column(Integer, nullable=False)
    v2_genesis_hash = Column(String(64), nullable=False)
    v2_genesis_sequence = Column(Integer, nullable=False)
    cutover_timestamp = Column(String(64), nullable=False)
    transition_hash = Column(String(64), nullable=False, unique=True)
    transition_signature = Column(Text, nullable=False)
    signing_key_id = Column(String(128), nullable=False)
    protocol_version = Column(Integer, nullable=False, default=2)


class LedgerStateEntity(Base):
    """Singleton schema foundation for the future database-level allocator."""

    __tablename__ = "ledger_state"

    singleton_id = Column(Integer, primary_key=True)
    next_sequence = Column(Integer, nullable=False, default=1)
    tip_hash = Column(String(64), nullable=False, default="0" * 64)
    state_version = Column(Integer, nullable=False, default=1)

    __table_args__ = (
        CheckConstraint("singleton_id = 1", name="ck_ledger_state_singleton"),
        CheckConstraint("next_sequence >= 1", name="ck_ledger_state_next_sequence"),
        CheckConstraint("length(tip_hash) = 64", name="ck_ledger_state_tip_hash_length"),
        CheckConstraint("state_version >= 1", name="ck_ledger_state_version"),
    )


def get_engine(database_url: str = "sqlite:///audit_ledger.db"):
    # SQLite connection with thread checking disabled for FastAPI compatibility
    if database_url.startswith("sqlite"):
        return create_engine(database_url, connect_args={"check_same_thread": False})
    return create_engine(database_url)


def run_migrations(engine) -> None:
    """Apply versioned migrations using the repository's Alembic environment."""
    from pathlib import Path
    from alembic import command
    from alembic.config import Config

    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    if "alembic_version" not in tables:
        validate_pre_migration_schema(engine)
    else:
        with engine.connect() as connection:
            revisions = [row[0] for row in connection.execute(text("SELECT version_num FROM alembic_version")).all()]
        if len(revisions) > 1:
            raise RuntimeError("Database has multiple migration revisions; refusing startup")
        if revisions:
            validate_current_schema(engine, revisions[0])

    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


def init_db(engine):
    """Compatibility entry point retained for tests and application startup."""
    run_migrations(engine)


def initialize_ledger_state(engine) -> None:
    """Initialize the singleton state only after validating any existing ledger."""
    from app.runtime_state import preflight_scope
    from app.security import Principal
    from app.services.verifier import ChainVerificationService

    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = Session()
    try:
        if engine.dialect.name == "sqlite":
            session.execute(text("BEGIN IMMEDIATE"))
        state = session.query(LedgerStateEntity).filter(LedgerStateEntity.singleton_id == 1).one_or_none()
        records = session.query(AuditRecordEntity).order_by(AuditRecordEntity.sequence_num.asc()).all()
        if records:
            with preflight_scope():
                result = ChainVerificationService.verify_ledger(
                    session,
                    principal=Principal("state-initializer", frozenset({"global_auditor"}), "state-initializer"),
                )
            if not result.intact:
                raise RuntimeError("Cannot initialize ledger state from an invalid audit history")
            expected_next = records[-1].sequence_num + 1
            expected_tip = records[-1].record_hash
        else:
            expected_next = 1
            expected_tip = "0" * 64
        if state is None:
            state = LedgerStateEntity(
                singleton_id=1,
                next_sequence=expected_next,
                tip_hash=expected_tip,
                state_version=1,
            )
            session.add(state)
            session.flush()
        elif (state.next_sequence, state.tip_hash) != (expected_next, expected_tip):
            raise RuntimeError("Existing ledger state does not match the validated audit history")
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session_factory(engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)

"""
Database models and connection engine for the append-only audit ledger.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy import (
    Boolean,
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


def get_engine(database_url: str = "sqlite:///audit_ledger.db"):
    # SQLite connection with thread checking disabled for FastAPI compatibility
    if database_url.startswith("sqlite"):
        return create_engine(database_url, connect_args={"check_same_thread": False})
    return create_engine(database_url)


def init_db(engine):
    """Creates tables and applies additive, nullable V2 migrations."""
    Base.metadata.create_all(bind=engine)
    if engine.dialect.name == "sqlite":
        existing = {column["name"] for column in inspect(engine).get_columns("audit_records")}
        with engine.begin() as connection:
            if "record_signature" not in existing:
                connection.execute(text("ALTER TABLE audit_records ADD COLUMN record_signature TEXT"))
            if "signing_key_id" not in existing:
                connection.execute(text("ALTER TABLE audit_records ADD COLUMN signing_key_id VARCHAR(128)"))
            additions = {
                "tenant_id": "VARCHAR(128)",
                "authenticated_subject": "VARCHAR(128)",
                "credential_id": "VARCHAR(128)",
                "attribution_mode": "VARCHAR(32)",
                "delegation_reason": "VARCHAR(512)",
                "protocol_version": "INTEGER NOT NULL DEFAULT 1",
            }
            for name, definition in additions.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE audit_records ADD COLUMN {name} {definition}"))
            transition_columns = {column["name"] for column in inspect(engine).get_columns("audit_epoch_transitions")}
            if "v2_genesis_sequence" not in transition_columns:
                connection.execute(text("ALTER TABLE audit_epoch_transitions ADD COLUMN v2_genesis_sequence INTEGER NOT NULL DEFAULT 0"))
            if "cutover_timestamp" not in transition_columns:
                connection.execute(text("ALTER TABLE audit_epoch_transitions ADD COLUMN cutover_timestamp VARCHAR(64) NOT NULL DEFAULT ''"))


def get_session_factory(engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)

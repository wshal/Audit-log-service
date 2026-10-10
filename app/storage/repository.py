"""
Append-only Audit Repository.
Enforces the strictly monotonic sequence increment and hash chain link creation.
Exposes no UPDATE or DELETE operations on core audit logs.
"""

import json
from functools import wraps
from typing import List, Optional, Tuple
from sqlalchemy import desc, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.crypto.hasher import (
    GENESIS_PREV_HASH,
    canonical_json,
    compute_event_content_hash,
    compute_record_chain_hash,
)
from app.models.schemas import AuditEventCreate, QueryFilters
from app.storage.database import AuditRecordEntity, LedgerStateEntity
from app.storage.database import AuditEpochTransitionEntity
from app.crypto.signer import sign_record_hash, signing_key_id
from app.authorization import authorize, authorize_legacy, require_operation_role, resolve_tenant, resolve_tenant_by_id
from app.runtime_state import ensure_ready


def _cleanup_append_failure(operation):
    @wraps(operation)
    def wrapped(repository, *args, **kwargs):
        try:
            return operation(repository, *args, **kwargs)
        except BaseException as original:
            if repository.session.info.get("ledger_lock_acquired"):
                AuditLedgerRepository.cleanup_failed_transaction(repository.session, original)
            raise
    return wrapped


class AuditLedgerRepository:
    def __init__(self, db_session: Session):
        self.session = db_session

    @staticmethod
    def _expected_state_from_records(session: Session) -> tuple[int, str]:
        records = session.query(AuditRecordEntity).order_by(AuditRecordEntity.sequence_num.asc()).all()
        expected_sequence = 1
        previous_hash = GENESIS_PREV_HASH
        for record in records:
            if record.sequence_num != expected_sequence or record.prev_hash != previous_hash:
                raise RuntimeError("Cannot initialize ledger state from an inconsistent audit history")
            expected_sequence += 1
            previous_hash = record.record_hash
        return expected_sequence, previous_hash

    @classmethod
    def lock_ledger_state(cls, session: Session) -> LedgerStateEntity:
        """Acquire the database-level writer lock before any ledger mutation.

        SQLite callers must invoke this before opening a transaction. Repeated
        calls within the same operation reuse the lock; an already-active
        transaction without this marker fails closed rather than bypassing
        ``BEGIN IMMEDIATE``.
        """
        dialect = session.bind.dialect.name
        if session.info.get("ledger_transaction_invalid"):
            raise RuntimeError("Ledger session was invalidated after rollback failure; close and recreate it")
        if session.info.get("ledger_lock_acquired"):
            return session.query(LedgerStateEntity).filter(LedgerStateEntity.singleton_id == 1).one()
        if dialect == "sqlite":
            if session.in_transaction():
                # SQLAlchemy cannot prove that an active transaction is
                # read-only: Core SQL can mutate without ORM dirty objects.
                # Never discard or combine caller-owned work with allocation.
                raise RuntimeError("Ledger allocator requires an explicitly ended caller transaction")
            session.execute(text("BEGIN IMMEDIATE"))
        else:
            if session.in_transaction():
                raise RuntimeError("Ledger allocator requires an explicitly ended caller transaction")
            session.execute(text(
                "INSERT INTO ledger_state (singleton_id, next_sequence, tip_hash, state_version) "
                "VALUES (1, 1, :genesis, 1) ON CONFLICT (singleton_id) DO NOTHING"
            ), {"genesis": GENESIS_PREV_HASH})
        try:
            state = session.query(LedgerStateEntity)
            if dialect != "sqlite":
                state = state.with_for_update()
            ledger_state = state.filter(LedgerStateEntity.singleton_id == 1).one_or_none()
            if ledger_state is None:
                has_records = session.query(AuditRecordEntity.id).first() is not None
                if has_records:
                    raise RuntimeError("Ledger state is missing for a populated ledger; run explicit initialization")
                ledger_state = LedgerStateEntity(singleton_id=1, next_sequence=1, tip_hash=GENESIS_PREV_HASH, state_version=1)
                session.add(ledger_state)
                session.flush()
            else:
                expected_next, expected_tip = cls._expected_state_from_records(session)
                if (ledger_state.next_sequence, ledger_state.tip_hash) != (expected_next, expected_tip):
                    raise RuntimeError("Ledger state does not match the audit history")
            session.info["ledger_lock_acquired"] = True
            return ledger_state
        except Exception:
            # The helper may have opened the transaction that owns the
            # database-level lock. Never leave that transaction holding the
            # SQLite writer lock after rejecting an inconsistent ledger.
            session.rollback()
            cls.release_ledger_lock(session)
            raise

    @staticmethod
    def release_ledger_lock(session: Session) -> None:
        session.info.pop("ledger_lock_acquired", None)

    @classmethod
    def cleanup_failed_transaction(cls, session: Session, original: BaseException) -> None:
        """Fail closed after an allocator-owned operation raises."""
        try:
            session.rollback()
        except BaseException as cleanup_error:
            session.info["ledger_transaction_invalid"] = True
            try:
                original.add_note(f"Allocator rollback failed: {cleanup_error!r}")
            except Exception:
                pass
        finally:
            cls.release_ledger_lock(session)

    @_cleanup_append_failure
    def append_event(self, event_in: AuditEventCreate, principal=None) -> AuditRecordEntity:
        """
        Atomically appends an audit record to the ledger.
        Fetches the previous tip of the chain, increments sequence_num,
        computes content hash and record hash, and persists the new block.
        """
        ensure_ready()
        if principal is None:
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Authenticated tenant scope is required")
        actor_substituted = bool(getattr(event_in, "impersonatedActorId", None)) or event_in.actorId != principal.subject
        if actor_substituted and (
            "audit_proxy" not in getattr(principal, "roles", ())
            or not getattr(event_in, "delegationReason", None)
        ):
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Explicit proxy delegation is required")
        if getattr(event_in, "tenantId", None):
            require_operation_role(principal, "write")
            authorize(principal, "write", event_in.tenantId, event_in.resourceType, event_in.resourceId)
        else:
            require_operation_role(principal, "write")
            authorize_legacy(principal, "write")
        ledger_state = self.lock_ledger_state(self.session)
        sequence_num = ledger_state.next_sequence
        prev_hash = ledger_state.tip_hash

        protocol_version = 2 if getattr(event_in, "tenantId", None) else 1
        attribution_mode = ("PROXY" if (getattr(event_in, "impersonatedActorId", None) or (principal and getattr(event_in, "actorId", None) != getattr(principal, "subject", None) and "audit_proxy" in getattr(principal, "roles", ()))) else "DIRECT") if principal else None
        authenticated_subject = getattr(principal, "subject", None)
        credential_id = getattr(principal, "credential_id", None)
        delegation_reason = getattr(event_in, "delegationReason", None)

        # Compute content hash. V2 binds caller attribution and protocol metadata.
        content_hash = compute_event_content_hash(
            event_type=event_in.eventType,
            actor_id=event_in.actorId,
            resource_type=event_in.resourceType,
            resource_id=event_in.resourceId,
            payload=event_in.payload,
            timestamp=event_in.timestamp,
            tenant_id=getattr(event_in, "tenantId", None),
            authenticated_subject=authenticated_subject,
            credential_id=credential_id,
            attribution_mode=attribution_mode,
            delegation_reason=delegation_reason,
            protocol_version=protocol_version,
        )
        legacy_records = self.session.query(AuditRecordEntity).filter(AuditRecordEntity.protocol_version == 1).order_by(AuditRecordEntity.sequence_num.desc()).all()
        legacy_tip = legacy_records[0].record_hash if legacy_records else GENESIS_PREV_HASH
        legacy_count = len(legacy_records)

        # Compute block record hash
        record_hash = compute_record_chain_hash(
            sequence_num=sequence_num,
            content_hash=content_hash,
            prev_hash=prev_hash,
        )

        try:
            record_entity = AuditRecordEntity(
                sequence_num=sequence_num,
                event_type=event_in.eventType,
                actor_id=event_in.actorId,
                resource_type=event_in.resourceType,
                resource_id=event_in.resourceId,
                payload_json=canonical_json(event_in.payload),
                timestamp=event_in.timestamp,
                content_hash=content_hash,
                prev_hash=prev_hash,
                record_hash=record_hash,
                record_signature=sign_record_hash(record_hash),
                signing_key_id=signing_key_id(),
                is_archived=False,
                archived_at=None,
                archival_reason=None,
                redaction_metadata_json=None,
                tenant_id=getattr(event_in, "tenantId", None),
                authenticated_subject=getattr(principal, "subject", None),
                credential_id=getattr(principal, "credential_id", None),
                attribution_mode=attribution_mode,
                delegation_reason=delegation_reason,
                protocol_version=protocol_version,
            )
        except BaseException as original:
            self.cleanup_failed_transaction(self.session, original)
            raise

        try:
            transition = None
            if getattr(event_in, "tenantId", None) and not self.session.query(AuditEpochTransitionEntity).first():
                from app.crypto.hasher import compute_sha256
                cutover_timestamp = event_in.timestamp
                transition_material = canonical_json({"legacyTipHash": legacy_tip, "legacyRecordCount": legacy_count, "v2GenesisHash": record_hash, "v2GenesisSequence": sequence_num, "cutoverTimestamp": cutover_timestamp, "protocolVersion": 2})
                transition_hash = compute_sha256(transition_material)
                transition = AuditEpochTransitionEntity(
                    legacy_tip_hash=legacy_tip, legacy_record_count=legacy_count,
                    v2_genesis_hash=record_hash, v2_genesis_sequence=sequence_num,
                    cutover_timestamp=cutover_timestamp, transition_hash=transition_hash,
                    transition_signature=sign_record_hash(transition_hash), signing_key_id=signing_key_id(), protocol_version=2,
                )
            self.session.add(record_entity)
            if transition is not None:
                self.session.add(transition)
            ledger_state.next_sequence = sequence_num + 1
            ledger_state.tip_hash = record_hash
            self.session.commit()
        except BaseException as original:
            self.cleanup_failed_transaction(self.session, original)
            raise
        self.release_ledger_lock(self.session)
        return record_entity

    def query_events(self, filters: QueryFilters, principal=None, tenant_id: str | None = None) -> Tuple[List[AuditRecordEntity], int]:
        """
        Filters audit records by actor, resource, eventType, timestamp ranges with pagination.
        """
        ensure_ready()
        require_operation_role(principal, "read")
        inferred = resolve_tenant_by_id(filters.resourceId) if filters.resourceId and not filters.resourceType else None
        if inferred:
            tenant_id = inferred[2]
        elif filters.resourceType and filters.resourceId:
            tenant_id = resolve_tenant(filters.resourceType, filters.resourceId)
        if tenant_id:
            authorize(principal, "read", tenant_id, filters.resourceType, filters.resourceId)
            query = self.session.query(AuditRecordEntity).filter(AuditRecordEntity.tenant_id == tenant_id)
        else:
            authorize_legacy(principal, "read")
            query = self.session.query(AuditRecordEntity).filter(AuditRecordEntity.protocol_version == 1)

        if filters.actorId:
            query = query.filter(AuditRecordEntity.actor_id == filters.actorId)
        if filters.resourceType:
            query = query.filter(AuditRecordEntity.resource_type == filters.resourceType)
        if filters.resourceId:
            query = query.filter(AuditRecordEntity.resource_id == filters.resourceId)
        if filters.eventType:
            query = query.filter(AuditRecordEntity.event_type == filters.eventType)
        if filters.fromTime:
            query = query.filter(AuditRecordEntity.timestamp >= filters.fromTime)
        if filters.toTime:
            query = query.filter(AuditRecordEntity.timestamp <= filters.toTime)

        total_count = query.count()

        results = (
            query.order_by(AuditRecordEntity.sequence_num.asc())
            .offset(filters.offset)
            .limit(filters.limit)
            .all()
        )

        return results, total_count

    def get_all_ordered_by_sequence(self, principal=None) -> List[AuditRecordEntity]:
        """Fetches all records in ascending sequence order for chain verification."""
        ensure_ready()
        if principal is None or "global_auditor" not in getattr(principal, "roles", ()):
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Global auditor capability is required")
        return (
            self.session.query(AuditRecordEntity)
            .order_by(AuditRecordEntity.sequence_num.asc())
            .all()
        )

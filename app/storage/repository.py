"""
Append-only Audit Repository.
Enforces the strictly monotonic sequence increment and hash chain link creation.
Exposes no UPDATE or DELETE operations on core audit logs.
"""

import json
from typing import List, Optional, Tuple
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.crypto.hasher import (
    GENESIS_PREV_HASH,
    canonical_json,
    compute_event_content_hash,
    compute_record_chain_hash,
)
from app.models.schemas import AuditEventCreate, QueryFilters
from app.storage.database import AuditRecordEntity


class AuditLedgerRepository:
    def __init__(self, db_session: Session):
        self.session = db_session

    def append_event(self, event_in: AuditEventCreate) -> AuditRecordEntity:
        """
        Atomically appends an audit record to the ledger.
        Fetches the previous tip of the chain, increments sequence_num,
        computes content hash and record hash, and persists the new block.
        """
        # Lock or retrieve the latest block in the ledger
        latest_record = (
            self.session.query(AuditRecordEntity)
            .order_by(desc(AuditRecordEntity.sequence_num))
            .first()
        )

        if latest_record is None:
            sequence_num = 1
            prev_hash = GENESIS_PREV_HASH
        else:
            sequence_num = latest_record.sequence_num + 1
            prev_hash = latest_record.record_hash

        # Compute content hash
        content_hash = compute_event_content_hash(
            event_type=event_in.eventType,
            actor_id=event_in.actorId,
            resource_type=event_in.resourceType,
            resource_id=event_in.resourceId,
            payload=event_in.payload,
            timestamp=event_in.timestamp,
        )

        # Compute block record hash
        record_hash = compute_record_chain_hash(
            sequence_num=sequence_num,
            content_hash=content_hash,
            prev_hash=prev_hash,
        )

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
            is_archived=False,
            archived_at=None,
            archival_reason=None,
            redaction_metadata_json=None,
        )

        self.session.add(record_entity)
        self.session.commit()
        self.session.refresh(record_entity)
        return record_entity

    def query_events(self, filters: QueryFilters) -> Tuple[List[AuditRecordEntity], int]:
        """
        Filters audit records by actor, resource, eventType, timestamp ranges with pagination.
        """
        query = self.session.query(AuditRecordEntity)

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

    def get_all_ordered_by_sequence(self) -> List[AuditRecordEntity]:
        """Fetches all records in ascending sequence order for chain verification."""
        return (
            self.session.query(AuditRecordEntity)
            .order_by(AuditRecordEntity.sequence_num.asc())
            .all()
        )

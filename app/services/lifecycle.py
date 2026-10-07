"""
Retention, Redaction, and Verifiable Bulk Export Service (Scenario B).
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.crypto.hasher import canonical_json, compute_sha256
from app.crypto.redaction import apply_structured_redaction
from app.models.retention_redaction import (
    RedactionResult,
    RetentionPolicyResult,
    VerifiableExportBundle,
)
from app.storage.database import AuditRecordEntity
from app.storage.repository import AuditLedgerRepository


class LifecycleAndExportService:
    @staticmethod
    def apply_retention_policy(
        session: Session,
        retention_days: int,
        reason: str,
    ) -> RetentionPolicyResult:
        """
        Soft-archives records older than `retention_days`.
        Crucially: Retains the chain structure, content_hash, and record_hash.
        Chain verification will confirm all records are present and unbroken without
        false-positive alerts for legitimately archived records.
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        cutoff_iso = cutoff_date.isoformat()

        records_to_archive = (
            session.query(AuditRecordEntity)
            .filter(AuditRecordEntity.timestamp < cutoff_iso)
            .filter(AuditRecordEntity.is_archived == False)
            .all()
        )

        archived_seqs = []
        now_iso = datetime.now(timezone.utc).isoformat()

        for rec in records_to_archive:
            rec.is_archived = True
            rec.archived_at = now_iso
            rec.archival_reason = reason
            archived_seqs.append(rec.sequence_num)

        session.commit()

        return RetentionPolicyResult(
            recordsArchived=len(archived_seqs),
            retentionCutoff=cutoff_iso,
            archivedSequenceNumbers=archived_seqs,
            status="COMPLETED",
        )

    @staticmethod
    def redact_record_fields(
        session: Session,
        sequence_num: int,
        field_paths: List[str],
        reason: str,
    ) -> RedactionResult:
        """
        Performs structured field redaction on a record:
        Replaces sensitive plaintext values with cryptographic commitments while preserving
        original contentHash and recordHash integrity in the blockchain.
        """
        rec = (
            session.query(AuditRecordEntity)
            .filter(AuditRecordEntity.sequence_num == sequence_num)
            .first()
        )
        if not rec:
            raise ValueError(f"Audit record with sequence {sequence_num} not found")

        current_payload = json.loads(rec.payload_json)
        existing_meta = json.loads(rec.redaction_metadata_json) if rec.redaction_metadata_json else None

        redacted_payload, metadata = apply_structured_redaction(
            payload=current_payload,
            fields_to_redact=field_paths,
            existing_metadata=existing_meta,
        )

        # Log redaction operation in metadata history
        if "history" not in metadata:
            metadata["history"] = []
        metadata["history"].append({
            "redactedAt": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "fields": field_paths,
        })

        rec.payload_json = canonical_json(redacted_payload)
        rec.redaction_metadata_json = canonical_json(metadata)

        session.commit()
        session.refresh(rec)

        return RedactionResult(
            sequenceNum=rec.sequence_num,
            redactedFields=field_paths,
            contentHashPreserved=rec.content_hash,
            recordHashPreserved=rec.record_hash,
            message="Field-level redaction applied. Cryptographic hashes preserved.",
        )

    @staticmethod
    def generate_verifiable_export(
        session: Session,
        actor_id: Optional[str] = None,
        resource_id: Optional[str] = None,
    ) -> VerifiableExportBundle:
        """
        Generates a self-contained, verifiable export bundle for a resourceId or actorId.
        The bundle includes chain metadata, sequence bounds, and a bundle-level integrity hash
        calculated over the canonical sequence of record hashes.
        """
        query = session.query(AuditRecordEntity)
        criteria = {}

        if actor_id:
            query = query.filter(AuditRecordEntity.actor_id == actor_id)
            criteria["actorId"] = actor_id
        if resource_id:
            query = query.filter(AuditRecordEntity.resource_id == resource_id)
            criteria["resourceId"] = resource_id

        records = query.order_by(AuditRecordEntity.sequence_num.asc()).all()

        record_dicts = [r.to_read_model() for r in records]
        
        # Calculate bundle-level integrity hash: SHA-256 over canonical list of record hashes
        record_hashes = [r.record_hash for r in records]
        bundle_hash = compute_sha256(canonical_json(record_hashes))

        return VerifiableExportBundle(
            exportId=str(uuid.uuid4()),
            generatedAt=datetime.now(timezone.utc).isoformat(),
            queryCriteria=criteria,
            totalRecords=len(records),
            startSequenceNum=records[0].sequence_num if records else None,
            endSequenceNum=records[-1].sequence_num if records else None,
            genesisPrevHash=records[0].prev_hash if records else "",
            records=record_dicts,
            bundleIntegrityHash=bundle_hash,
        )

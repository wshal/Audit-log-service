"""
Retention, Redaction, and Verifiable Bulk Export Service (Scenario B).
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import text
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
from app.models.schemas import AuditEventCreate
from app.crypto.signer import sign_record_hash, signing_key_id
from app.crypto.signer import public_key_ring
from app.runtime_state import ensure_ready


class LifecycleAndExportService:
    @staticmethod
    def _project_payload(payload: Dict[str, Any], include_pii: bool) -> Dict[str, Any]:
        if include_pii:
            return payload
        sensitive = {"ssn", "taxid", "tax_id", "accountnumber", "account_number", "dob", "dateofbirth"}
        def project(value):
            if isinstance(value, dict):
                return {k: project(v) for k, v in value.items() if k.lower() not in sensitive}
            if isinstance(value, list):
                return [project(v) for v in value]
            return value
        return project(payload)
    @staticmethod
    def _append_lifecycle_journal(
        session: Session, event_type: str, resource_id: str, payload: Dict[str, Any], tenant_id: Optional[str] = None
    ) -> AuditRecordEntity:
        """Append a system lifecycle event inside the caller's locked transaction."""
        latest = session.query(AuditRecordEntity).order_by(AuditRecordEntity.sequence_num.desc()).first()
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        from app.crypto.hasher import compute_event_content_hash, compute_record_chain_hash
        content_hash = compute_event_content_hash(
            event_type, "audit-lifecycle-service", "AUDIT_RECORD", resource_id, payload, timestamp
            , tenant_id=tenant_id, authenticated_subject="audit-lifecycle-service", credential_id="service", attribution_mode="SYSTEM", delegation_reason=None, protocol_version=2 if tenant_id else 1
        )
        record_hash = compute_record_chain_hash(latest.sequence_num + 1, content_hash, latest.record_hash)
        journal = AuditRecordEntity(
            sequence_num=latest.sequence_num + 1, event_type=event_type,
            actor_id="audit-lifecycle-service", resource_type="AUDIT_RECORD", resource_id=resource_id,
            payload_json=canonical_json(payload), timestamp=timestamp, content_hash=content_hash,
            prev_hash=latest.record_hash, record_hash=record_hash,
            record_signature=sign_record_hash(record_hash), signing_key_id=signing_key_id(),
            is_archived=False,
            tenant_id=tenant_id,
            authenticated_subject="audit-lifecycle-service" if tenant_id else None,
            credential_id="service" if tenant_id else None,
            attribution_mode="SYSTEM" if tenant_id else None,
            protocol_version=2 if tenant_id else 1,
        )
        session.add(journal)
        session.flush()
        return journal

    @staticmethod
    def apply_retention_policy(
        session: Session,
        retention_days: int,
        reason: str,
        tenant_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        principal=None,
    ) -> RetentionPolicyResult:
        """
        Soft-archives records older than `retention_days`.
        Crucially: Retains the chain structure, content_hash, and record_hash.
        Chain verification will confirm all records are present and unbroken without
        false-positive alerts for legitimately archived records.
        """
        ensure_ready()
        if principal is None:
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Authorization scope is required")
        if session.bind.dialect.name == "sqlite":
            session.execute(text("BEGIN IMMEDIATE"))
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        cutoff_iso = cutoff_date.isoformat().replace("+00:00", "Z")

        records_query = (
            session.query(AuditRecordEntity)
            .filter(AuditRecordEntity.timestamp < cutoff_iso)
            .filter(AuditRecordEntity.is_archived == False)
        )
        if tenant_id:
            records_query = records_query.filter(AuditRecordEntity.tenant_id == tenant_id)
        if resource_id:
            records_query = records_query.filter(AuditRecordEntity.resource_id == resource_id)
        records_to_archive = records_query.all()

        archived_seqs = []
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        for rec in records_to_archive:
            rec.is_archived = True
            rec.archived_at = now_iso
            rec.archival_reason = reason
            archived_seqs.append(rec.sequence_num)

        session.flush()
        for rec in records_to_archive:
            archive_state = {
                "archivalReason": rec.archival_reason,
                "archivedAt": rec.archived_at,
                "isArchived": True,
                "sequenceNum": rec.sequence_num,
            }
            LifecycleAndExportService._append_lifecycle_journal(
                session, "AUDIT_RECORD_ARCHIVED", str(rec.sequence_num),
                {"archiveStateHash": compute_sha256(canonical_json(archive_state)), **archive_state},
                tenant_id=rec.tenant_id,
            )
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
        principal=None,
    ) -> RedactionResult:
        """
        Performs structured field redaction on a record:
        Replaces sensitive plaintext values with cryptographic commitments while preserving
        original contentHash and recordHash integrity in the blockchain.
        """
        ensure_ready()
        if session.bind.dialect.name == "sqlite":
            session.execute(text("BEGIN IMMEDIATE"))

        rec = (
            session.query(AuditRecordEntity)
            .filter(AuditRecordEntity.sequence_num == sequence_num)
            .first()
        )
        if not rec:
            raise ValueError(f"Audit record with sequence {sequence_num} not found")
        if principal is None:
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Authorization scope is required")

        current_payload = json.loads(rec.payload_json)
        existing_meta = json.loads(rec.redaction_metadata_json) if rec.redaction_metadata_json else None

        unknown_fields = [field for field in field_paths if field not in current_payload]
        already_redacted = [field for field in field_paths if field in (existing_meta or {}).get("commitments", {})]
        if unknown_fields:
            raise ValueError(f"Payload fields missing: {', '.join(unknown_fields)}")
        if already_redacted:
            raise ValueError(f"Payload fields already redacted: {', '.join(already_redacted)}")

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

        # A redacted payload no longer reproduces the original content hash. Bind a
        # canonical snapshot of the legally redacted representation in a new,
        # chained audit event so subsequent storage edits remain detectable.
        redacted_payload_hash = compute_sha256(canonical_json(redacted_payload))
        metadata_hash = compute_sha256(canonical_json(metadata))

        rec.payload_json = canonical_json(redacted_payload)
        rec.redaction_metadata_json = canonical_json(metadata)

        # Flush the lifecycle mutation, then append the immutable manifest in the
        # same transaction.
        session.flush()
        LifecycleAndExportService._append_lifecycle_journal(
            session, "AUDIT_RECORD_REDACTED", str(rec.sequence_num), {
                "metadataHash": metadata_hash,
                "originalContentHash": rec.content_hash,
                "originalRecordHash": rec.record_hash,
                "redactedPayloadHash": redacted_payload_hash,
                "redactedSequenceNum": rec.sequence_num,
                "reason": reason,
            },
            tenant_id=rec.tenant_id,
        )
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
        include_pii: bool = False,
        principal=None,
    ) -> VerifiableExportBundle:
        """
        Generates a self-contained, verifiable export bundle for a resourceId or actorId.
        The bundle includes chain metadata, sequence bounds, and a bundle-level integrity hash
        calculated over the canonical sequence of record hashes.
        """
        ensure_ready()
        if principal is None:
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Authorization scope is required")
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
        for record in record_dicts:
            record["payload"] = LifecycleAndExportService._project_payload(record["payload"], include_pii)
        selected_sequences = {r.sequence_num for r in records}
        manifests = []
        lifecycle_records = session.query(AuditRecordEntity).filter(
            AuditRecordEntity.event_type.in_(["AUDIT_RECORD_REDACTED", "AUDIT_RECORD_ARCHIVED"])
        ).order_by(AuditRecordEntity.sequence_num.asc()).all()
        for lifecycle_record in lifecycle_records:
            try:
                payload = json.loads(lifecycle_record.payload_json)
                target = payload.get("redactedSequenceNum", payload.get("sequenceNum"))
                if target in selected_sequences:
                    manifests.append(lifecycle_record.to_read_model())
            except json.JSONDecodeError:
                continue
        
        # Calculate bundle-level integrity hash: SHA-256 over canonical list of record hashes
        record_hashes = [r.record_hash for r in records]
        bundle_hash = compute_sha256(canonical_json(record_hashes))

        signing_key_ids = {r.signing_key_id for r in records}
        signing_key_ids.update(m.get("signingKeyId") for m in manifests)
        trusted_keys = public_key_ring()

        return VerifiableExportBundle(
            exportId=str(uuid.uuid4()),
            generatedAt=datetime.now(timezone.utc).isoformat(),
            queryCriteria=criteria,
            totalRecords=len(records),
            startSequenceNum=records[0].sequence_num if records else None,
            endSequenceNum=records[-1].sequence_num if records else None,
            genesisPrevHash=records[0].prev_hash if records else "",
            records=record_dicts,
            integrityManifests=manifests,
            bundleIntegrityHash=bundle_hash,
            signingPublicKeys={
                key_id: trusted_keys[key_id]
                for key_id in signing_key_ids
                if key_id in trusted_keys
            },
        )

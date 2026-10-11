"""
Retention, Redaction, and Verifiable Bulk Export Service (Scenario B).
"""

import json
import uuid
from functools import wraps
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from fastapi import HTTPException
from sqlalchemy import and_, or_, text
from sqlalchemy.orm import Session

from app.crypto.hasher import canonical_json, compute_sha256
from app.crypto.redaction import apply_structured_redaction
from app.models.retention_redaction import (
    RedactionResult,
    RetentionPolicyResult,
    VerifiableExportBundle,
)
from app.storage.database import AuditRecordEntity, LedgerStateEntity
from app.storage.repository import AuditLedgerRepository
from app.models.schemas import AuditEventCreate, parse_timestamp, strict_json_loads
from app.crypto.signer import sign_record_hash, signing_key_id
from app.crypto.signer import public_key_ring
from app.runtime_state import ensure_ready
from app.authorization import authorize, authorize_legacy, authorize_record, require_operation_role, resolve_tenant_by_id


def _cleanup_allocator_failure(operation):
    """Rollback only a lock acquired by the wrapped lifecycle operation."""
    @wraps(operation)
    def wrapped(session, *args, **kwargs):
        try:
            return operation(session, *args, **kwargs)
        except BaseException as original:
            if session.info.get("ledger_lock_acquired"):
                AuditLedgerRepository.cleanup_failed_transaction(session, original)
            raise
    return wrapped


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
        """Append inside a caller-owned allocator lock and transaction."""
        if not session.info.get("ledger_lock_acquired"):
            raise RuntimeError("Lifecycle journal requires an acquired ledger allocator lock")
        ledger_state = session.query(LedgerStateEntity).filter(LedgerStateEntity.singleton_id == 1).one()
        sequence_num = ledger_state.next_sequence
        prev_hash = ledger_state.tip_hash
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        from app.crypto.hasher import compute_event_content_hash, compute_record_chain_hash
        content_hash = compute_event_content_hash(
            event_type, "audit-lifecycle-service", "AUDIT_RECORD", resource_id, payload, timestamp
            , tenant_id=tenant_id, authenticated_subject="audit-lifecycle-service", credential_id="service", attribution_mode="SYSTEM", delegation_reason=None, protocol_version=2 if tenant_id else 1
        )
        record_hash = compute_record_chain_hash(sequence_num, content_hash, prev_hash)
        journal = AuditRecordEntity(
            sequence_num=sequence_num, event_type=event_type,
            actor_id="audit-lifecycle-service", resource_type="AUDIT_RECORD", resource_id=resource_id,
            payload_json=canonical_json(payload), timestamp=timestamp, content_hash=content_hash,
            prev_hash=prev_hash, record_hash=record_hash,
            record_signature=sign_record_hash(record_hash), signing_key_id=signing_key_id(),
            is_archived=False,
            tenant_id=tenant_id,
            authenticated_subject="audit-lifecycle-service" if tenant_id else None,
            credential_id="service" if tenant_id else None,
            attribution_mode="SYSTEM" if tenant_id else None,
            protocol_version=2 if tenant_id else 1,
        )
        session.add(journal)
        ledger_state.next_sequence = sequence_num + 1
        ledger_state.tip_hash = record_hash
        session.flush()
        return journal

    @staticmethod
    @_cleanup_allocator_failure
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
        require_operation_role(principal, "retain")
        if tenant_id or resource_id:
            if not tenant_id or not resource_id:
                from app.authorization import deny
                deny("A tenant and resource scope are required")
            inferred = resolve_tenant_by_id(resource_id)
            if not inferred or inferred[2] != tenant_id:
                from app.authorization import deny
                deny("Unknown or foreign resource")
            authorize(principal, "retain", tenant_id, inferred[0], resource_id)
        else:
            authorize_legacy(principal, "retain")
        AuditLedgerRepository.lock_ledger_state(session)
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        cutoff_iso = cutoff_date.isoformat().replace("+00:00", "Z")

        records_query = session.query(AuditRecordEntity).filter(AuditRecordEntity.is_archived == False)
        if tenant_id:
            records_query = records_query.filter(AuditRecordEntity.tenant_id == tenant_id)
        if resource_id:
            records_query = records_query.filter(AuditRecordEntity.resource_id == resource_id)
        cutoff_instant = parse_timestamp(cutoff_iso)
        records_to_archive = [
            record for record in records_query.all()
            if parse_timestamp(record.timestamp) < cutoff_instant
        ]

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
        AuditLedgerRepository.release_ledger_lock(session)

        return RetentionPolicyResult(
            recordsArchived=len(archived_seqs),
            retentionCutoff=cutoff_iso,
            archivedSequenceNumbers=archived_seqs,
            status="COMPLETED",
        )

    @staticmethod
    @_cleanup_allocator_failure
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
        require_operation_role(principal, "redact")
        scope_predicates = []
        if "global_auditor" in getattr(principal, "roles", ()):
            scope_predicates.append(AuditRecordEntity.protocol_version == 1)
        for grant in getattr(principal, "tenant_grants", ()):
            if grant.get("tenantId") is None:
                continue
            actions = set(grant.get("actions", ()))
            if "redact" not in actions and "*" not in actions:
                continue
            scopes = grant.get("resourceScopes") or []
            if not scopes:
                scope_predicates.append(AuditRecordEntity.tenant_id == grant["tenantId"])
                continue
            for scope in scopes:
                predicates = [AuditRecordEntity.tenant_id == grant["tenantId"]]
                if scope.get("resourceType"):
                    predicates.append(AuditRecordEntity.resource_type == scope["resourceType"])
                ids = scope.get("resourceIds") or scope.get("resources") or "*"
                if ids != "*":
                    predicates.append(AuditRecordEntity.resource_id.in_(list(ids)))
                scope_predicates.append(and_(*predicates))
        if not scope_predicates:
            raise ValueError("Audit record not found")
        AuditLedgerRepository.lock_ledger_state(session)
        rec = session.query(AuditRecordEntity).filter(
            AuditRecordEntity.sequence_num == sequence_num,
            or_(*scope_predicates),
        ).first()
        if not rec:
            raise ValueError("Audit record not found")
        try:
            authorize_record(principal, "redact", rec)
        except HTTPException:
            raise ValueError("Audit record not found")

        current_payload = strict_json_loads(rec.payload_json)
        existing_meta = strict_json_loads(rec.redaction_metadata_json) if rec.redaction_metadata_json else None

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
        result = RedactionResult(
            sequenceNum=rec.sequence_num,
            redactedFields=field_paths,
            contentHashPreserved=rec.content_hash,
            recordHashPreserved=rec.record_hash,
            message="Field-level redaction applied. Cryptographic hashes preserved.",
        )
        session.commit()
        AuditLedgerRepository.release_ledger_lock(session)
        return result

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
        require_operation_role(principal, "export", include_pii=include_pii)
        if not actor_id and not resource_id:
            from app.authorization import deny
            deny("An actor or resource scope is required")
        query = session.query(AuditRecordEntity)
        criteria = {}

        if actor_id:
            query = query.filter(AuditRecordEntity.actor_id == actor_id)
            criteria["actorId"] = actor_id
        if resource_id:
            query = query.filter(AuditRecordEntity.resource_id == resource_id)
            criteria["resourceId"] = resource_id

        if resource_id:
            inferred = resolve_tenant_by_id(resource_id)
            if inferred:
                authorize(principal, "export", inferred[2], inferred[0], resource_id)
                query = query.filter(AuditRecordEntity.tenant_id == inferred[2])
            else:
                authorize_legacy(principal, "export", include_pii=include_pii)
                query = query.filter(AuditRecordEntity.protocol_version == 1)
        elif getattr(principal, "tenant_grants", ()):
            from app.authorization import deny
            deny("Tenant-scoped export requires a resource scope")
        else:
            authorize_legacy(principal, "export", include_pii=include_pii)
            query = query.filter(AuditRecordEntity.protocol_version == 1)

        records = query.order_by(AuditRecordEntity.sequence_num.asc()).all()

        record_dicts = [r.to_read_model() for r in records]
        for record in record_dicts:
            record["payload"] = LifecycleAndExportService._project_payload(record["payload"], include_pii)
        selected_sequences = {r.sequence_num for r in records}
        manifests = []
        lifecycle_query = session.query(AuditRecordEntity).filter(
            AuditRecordEntity.event_type.in_(["AUDIT_RECORD_REDACTED", "AUDIT_RECORD_ARCHIVED"])
        )
        # Apply the same authorization boundary to lifecycle evidence before
        # loading rows.  Python-side filtering alone would still read unrelated
        # tenant manifests through a direct service invocation.
        if resource_id:
            inferred_resource = resolve_tenant_by_id(resource_id)
            if inferred_resource:
                lifecycle_query = lifecycle_query.filter(
                    AuditRecordEntity.tenant_id == inferred_resource[2]
                )
            else:
                lifecycle_query = lifecycle_query.filter(AuditRecordEntity.protocol_version == 1)
        else:
            lifecycle_query = lifecycle_query.filter(AuditRecordEntity.protocol_version == 1)
        lifecycle_records = lifecycle_query.order_by(AuditRecordEntity.sequence_num.asc()).all()
        for lifecycle_record in lifecycle_records:
            try:
                payload = strict_json_loads(lifecycle_record.payload_json)
                target = payload.get("redactedSequenceNum", payload.get("sequenceNum"))
                if target in selected_sequences:
                    manifests.append(lifecycle_record.to_read_model())
            except (json.JSONDecodeError, ValueError):
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

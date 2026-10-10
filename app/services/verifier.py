"""
Chain Verification Service (Scenario A).
Walks the full append-only audit ledger to verify:
1. Genesis hash conformity for sequence #1
2. Unbroken cryptographic linkage (prev_hash[i] == record_hash[i-1])
3. Sequential integrity (sequence_num[i] == sequence_num[i-1] + 1)
4. Record content fidelity (recomputed content_hash == stored content_hash, handling redactions if present)
5. Block hash fidelity (recomputed record_hash == stored record_hash)
"""

import json
from typing import List, Optional
from sqlalchemy.orm import Session

from app.crypto.hasher import (
    GENESIS_PREV_HASH,
    canonical_json,
    compute_event_content_hash,
    compute_record_chain_hash,
    compute_sha256,
)
from app.crypto.signer import public_key_for_id, verify_record_signature
from app.models.schemas import VerificationResult, ViolationType
from app.storage.database import AuditRecordEntity
from app.storage.database import AuditEpochTransitionEntity
from app.storage.repository import AuditLedgerRepository
from app.runtime_state import ensure_ready


class ChainVerificationService:
    @staticmethod
    def verify_ledger(session: Session, principal=None) -> VerificationResult:
        ensure_ready()
        if principal is None or "global_auditor" not in getattr(principal, "roles", ()):
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Global auditor capability is required")
        repo = AuditLedgerRepository(session)
        records: List[AuditRecordEntity] = repo.get_all_ordered_by_sequence(principal=principal)

        v2_records = [r for r in records if (r.protocol_version or 1) >= 2]
        if v2_records:
            transition = session.query(AuditEpochTransitionEntity).order_by(AuditEpochTransitionEntity.id.asc()).first()
            if transition is None or transition.v2_genesis_hash != v2_records[0].record_hash:
                return VerificationResult(intact=False, recordsVerified=0, violationType=ViolationType.CHAIN_LINK_BROKEN, details="Missing or invalid V1/V2 transition evidence.")
            material = canonical_json({"legacyTipHash": transition.legacy_tip_hash, "legacyRecordCount": transition.legacy_record_count, "v2GenesisHash": transition.v2_genesis_hash, "v2GenesisSequence": transition.v2_genesis_sequence, "cutoverTimestamp": transition.cutover_timestamp, "protocolVersion": 2})
            if compute_sha256(material) != transition.transition_hash:
                return VerificationResult(intact=False, recordsVerified=0, violationType=ViolationType.RECORD_HASH_MISMATCH, details="V1/V2 transition evidence was tampered with.")
            key = public_key_for_id(transition.signing_key_id)
            if not key or not verify_record_signature(transition.transition_hash, transition.transition_signature, key):
                return VerificationResult(intact=False, recordsVerified=0, violationType=ViolationType.SIGNATURE_MISMATCH, details="V1/V2 transition signature is invalid.")
            v1_records = [r for r in records if (r.protocol_version or 1) == 1]
            if len(v1_records) != transition.legacy_record_count or (v1_records[-1].record_hash if v1_records else GENESIS_PREV_HASH) != transition.legacy_tip_hash:
                return VerificationResult(intact=False, recordsVerified=0, violationType=ViolationType.CHAIN_LINK_BROKEN, details="Transition does not match the actual V1 epoch.")
            if v2_records[0].sequence_num != transition.v2_genesis_sequence:
                return VerificationResult(intact=False, recordsVerified=0, violationType=ViolationType.SEQUENCE_DISCONTINUITY, details="Transition does not match the first V2 sequence.")

        total = len(records)
        if total == 0:
            return VerificationResult(
                intact=True,
                recordsVerified=0,
                firstBrokenSequence=None,
                firstBrokenRecordId=None,
                violationType=ViolationType.NONE,
                details="Ledger is empty. Genesis state intact.",
            )

        expected_prev_hash = GENESIS_PREV_HASH
        redaction_manifests = {}
        archive_manifests = {}
        for manifest in records:
            if manifest.event_type == "AUDIT_RECORD_ARCHIVED":
                try:
                    payload = json.loads(manifest.payload_json)
                    archive_manifests.setdefault(payload["sequenceNum"], []).append(payload)
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue
            elif manifest.event_type == "AUDIT_RECORD_REDACTED":
                try:
                    payload = json.loads(manifest.payload_json)
                    target = payload["redactedSequenceNum"]
                    redaction_manifests.setdefault(target, []).append(payload)
                except (json.JSONDecodeError, KeyError, TypeError):
                    # The manifest's own content-hash verification below will report it.
                    continue

        for idx, rec in enumerate(records):
            expected_seq = idx + 1

            # 1. Check sequence monotonicity and gaps
            if rec.sequence_num != expected_seq:
                return VerificationResult(
                    intact=False,
                    recordsVerified=idx,
                    firstBrokenSequence=rec.sequence_num,
                    firstBrokenRecordId=rec.id,
                    violationType=ViolationType.SEQUENCE_DISCONTINUITY,
                    details=(
                        f"Sequence discontinuity at index {idx}: expected sequence {expected_seq}, "
                        f"found {rec.sequence_num}."
                    ),
                )

            # 2. Check genesis block or previous hash link
            if idx == 0:
                if rec.prev_hash != GENESIS_PREV_HASH:
                    return VerificationResult(
                        intact=False,
                        recordsVerified=0,
                        firstBrokenSequence=rec.sequence_num,
                        firstBrokenRecordId=rec.id,
                        violationType=ViolationType.GENESIS_MISMATCH,
                        details=(
                            f"Genesis block prev_hash invalid: expected {GENESIS_PREV_HASH}, "
                            f"found {rec.prev_hash}."
                        ),
                    )
            else:
                if rec.prev_hash != expected_prev_hash:
                    return VerificationResult(
                        intact=False,
                        recordsVerified=idx,
                        firstBrokenSequence=rec.sequence_num,
                        firstBrokenRecordId=rec.id,
                        violationType=ViolationType.CHAIN_LINK_BROKEN,
                        details=(
                            f"Chain link broken at sequence {rec.sequence_num}: "
                            f"recorded prev_hash '{rec.prev_hash}' does not match prior record_hash '{expected_prev_hash}'."
                        ),
                    )

            # 3. Check content integrity (with redaction handling if applicable)
            try:
                payload = json.loads(rec.payload_json)
                redaction_meta = json.loads(rec.redaction_metadata_json) if rec.redaction_metadata_json else None
            except json.JSONDecodeError:
                return VerificationResult(
                    intact=False, recordsVerified=idx,
                    firstBrokenSequence=rec.sequence_num, firstBrokenRecordId=rec.id,
                    violationType=ViolationType.MALFORMED_RECORD,
                    details="Stored JSON is malformed.",
                )

            # If the record has NOT undergone field-level redaction, recomputing content hash must match stored content_hash
            if not redaction_meta:
                recomputed_content_hash = compute_event_content_hash(
                    event_type=rec.event_type,
                    actor_id=rec.actor_id,
                    resource_type=rec.resource_type,
                    resource_id=rec.resource_id,
                    payload=payload,
                    timestamp=rec.timestamp,
                    tenant_id=rec.tenant_id if (rec.protocol_version or 1) >= 2 else None,
                    authenticated_subject=rec.authenticated_subject if (rec.protocol_version or 1) >= 2 else None,
                    credential_id=rec.credential_id if (rec.protocol_version or 1) >= 2 else None,
                    attribution_mode=rec.attribution_mode if (rec.protocol_version or 1) >= 2 else None,
                    delegation_reason=rec.delegation_reason if (rec.protocol_version or 1) >= 2 else None,
                    protocol_version=rec.protocol_version if (rec.protocol_version or 1) >= 2 else None,
                )
                if recomputed_content_hash != rec.content_hash:
                    return VerificationResult(
                        intact=False,
                        recordsVerified=idx,
                        firstBrokenSequence=rec.sequence_num,
                        firstBrokenRecordId=rec.id,
                        violationType=ViolationType.CONTENT_HASH_MISMATCH,
                        details=(
                            f"Content tampering detected at sequence {rec.sequence_num}: "
                            f"recomputed content_hash '{recomputed_content_hash}' != stored '{rec.content_hash}'."
                        ),
                    )
            else:
                payload_hash = compute_sha256(canonical_json(payload))
                metadata_hash = compute_sha256(canonical_json(redaction_meta))
                manifests = redaction_manifests.get(rec.sequence_num, [])
                matching_manifest = next((m for m in manifests if (
                    m.get("originalContentHash") == rec.content_hash
                    and m.get("originalRecordHash") == rec.record_hash
                    and m.get("redactedPayloadHash") == payload_hash
                    and m.get("metadataHash") == metadata_hash
                )), None)
                if not matching_manifest:
                    return VerificationResult(
                        intact=False, recordsVerified=idx,
                        firstBrokenSequence=rec.sequence_num, firstBrokenRecordId=rec.id,
                        violationType=ViolationType.CONTENT_HASH_MISMATCH,
                        details="Redacted content or its metadata does not match an immutable redaction manifest.",
                    )

            archive_state = {
                "archivalReason": rec.archival_reason,
                "archivedAt": rec.archived_at,
                "isArchived": True,
                "sequenceNum": rec.sequence_num,
            }
            archived_manifests = archive_manifests.get(rec.sequence_num, [])
            archive_matches = any(m.get("archiveStateHash") == compute_sha256(canonical_json(archive_state)) for m in archived_manifests)
            if rec.is_archived and not archive_matches:
                return VerificationResult(
                    intact=False, recordsVerified=idx, firstBrokenSequence=rec.sequence_num,
                    firstBrokenRecordId=rec.id, violationType=ViolationType.UNAUTHORIZED_ARCHIVAL,
                    details="Archived record does not match an immutable archival manifest.",
                )
            if not rec.is_archived and archived_manifests:
                return VerificationResult(
                    intact=False, recordsVerified=idx, firstBrokenSequence=rec.sequence_num,
                    firstBrokenRecordId=rec.id, violationType=ViolationType.UNAUTHORIZED_ARCHIVAL,
                    details="An archival manifest exists but the record is no longer archived.",
                )

            # 4. Check block record hash integrity
            recomputed_record_hash = compute_record_chain_hash(
                sequence_num=rec.sequence_num,
                content_hash=rec.content_hash,
                prev_hash=rec.prev_hash,
            )
            if recomputed_record_hash != rec.record_hash:
                return VerificationResult(
                    intact=False,
                    recordsVerified=idx,
                    firstBrokenSequence=rec.sequence_num,
                    firstBrokenRecordId=rec.id,
                    violationType=ViolationType.RECORD_HASH_MISMATCH,
                    details=(
                        f"Record block hash mismatch at sequence {rec.sequence_num}: "
                        f"recomputed record_hash '{recomputed_record_hash}' != stored '{rec.record_hash}'."
                    ),
                )

            # A valid signature makes recomputing a forged chain insufficient for
            # a database-only attacker. The verification key is configured outside
            # the ledger and is included in export bundles for offline checks.
            public_key = public_key_for_id(rec.signing_key_id)
            if not rec.record_signature or not public_key or not verify_record_signature(
                rec.record_hash, rec.record_signature, public_key
            ):
                return VerificationResult(
                    intact=False,
                    recordsVerified=idx,
                    firstBrokenSequence=rec.sequence_num,
                    firstBrokenRecordId=rec.id,
                    violationType=ViolationType.SIGNATURE_MISMATCH,
                    details="Record signature is missing or invalid for the configured signing key.",
                )

            # Update expected_prev_hash for next iteration
            expected_prev_hash = rec.record_hash

        return VerificationResult(
            intact=True,
            recordsVerified=total,
            firstBrokenSequence=None,
            firstBrokenRecordId=None,
            violationType=ViolationType.NONE,
            details=f"Verification successful. All {total} audit records form an intact, cryptographic hash chain.",
        )

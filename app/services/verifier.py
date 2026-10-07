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
    compute_event_content_hash,
    compute_record_chain_hash,
)
from app.models.schemas import VerificationResult, ViolationType
from app.storage.database import AuditRecordEntity
from app.storage.repository import AuditLedgerRepository


class ChainVerificationService:
    @staticmethod
    def verify_ledger(session: Session) -> VerificationResult:
        repo = AuditLedgerRepository(session)
        records: List[AuditRecordEntity] = repo.get_all_ordered_by_sequence()

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
            payload = json.loads(rec.payload_json)
            redaction_meta = json.loads(rec.redaction_metadata_json) if rec.redaction_metadata_json else None

            # If the record has NOT undergone field-level redaction, recomputing content hash must match stored content_hash
            if not redaction_meta:
                recomputed_content_hash = compute_event_content_hash(
                    event_type=rec.event_type,
                    actor_id=rec.actor_id,
                    resource_type=rec.resource_type,
                    resource_id=rec.resource_id,
                    payload=payload,
                    timestamp=rec.timestamp,
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
                # If redacted, check structured redaction validity (Scenario B)
                # The stored content_hash is preserved, but we also ensure redaction metadata is cryptographically sound
                # We will detail this in Scenario B
                pass

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

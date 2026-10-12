"""Checkpoint authenticity and ledger-prefix comparison.

The comparison is intentionally separate from ``ChainVerificationService``:
normal full-ledger verification remains unchanged, while this path answers only
whether a trusted signed checkpoint anchors the local prefix.
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import ValidationError
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.checkpoint import (
    Checkpoint,
    CheckpointSignatureError,
    CheckpointVerificationResult,
    CheckpointVerificationStatus,
    verify_checkpoint_signature,
)
from app.crypto.hasher import GENESIS_PREV_HASH
from app.storage.database import AuditRecordEntity, LedgerStateEntity
from app.services.verifier import ChainVerificationService


def verify_checkpoint_against_ledger(
    session: Session,
    checkpoint: Checkpoint | Mapping[str, object] | None,
    *,
    expected_ledger_id: str,
    trusted_public_keys: Mapping[str, str],
    integrity_principal=None,
) -> CheckpointVerificationResult:
    """Compare a trusted checkpoint with the local ledger without changing state.

    A longer local ledger is reported as ``UNANCHORED_SUFFIX``: the signed
    prefix matches, but the suffix has no independently retained checkpoint.
    This function does not alter readiness, quarantine, append, or recovery
    behavior.
    """
    if checkpoint is None:
        return CheckpointVerificationResult(
            CheckpointVerificationStatus.NO_CHECKPOINT,
            "No external checkpoint was supplied; checkpoint verification was not performed.",
        )
    try:
        value = checkpoint if isinstance(checkpoint, Checkpoint) else Checkpoint.model_validate(checkpoint)
    except ValidationError as exc:
        return CheckpointVerificationResult(
            CheckpointVerificationStatus.MALFORMED,
            f"Checkpoint schema is malformed: {exc.errors()[0].get('msg', 'invalid checkpoint')}",
        )
    if value.ledgerId != expected_ledger_id:
        return CheckpointVerificationResult(
            CheckpointVerificationStatus.IDENTITY_MISMATCH,
            "Checkpoint ledger identity does not match the requested ledger.",
        )
    try:
        verify_checkpoint_signature(value, trusted_public_keys)
    except CheckpointSignatureError:
        return CheckpointVerificationResult(
            CheckpointVerificationStatus.INVALID_SIGNATURE,
            "Checkpoint signature could not be verified by trusted key material.",
        )

    # Reuse the authoritative verifier rather than duplicating a partial
    # chain/state/signature implementation here.  The caller must provide the
    # same explicit global-auditor principal required by ordinary verification;
    # no checkpoint-specific authorization bypass is created.
    try:
        integrity = ChainVerificationService.verify_ledger(
            session, principal=integrity_principal
        )
    except Exception as exc:
        return CheckpointVerificationResult(
            CheckpointVerificationStatus.LOCAL_LEDGER_INVALID,
            f"Local ledger integrity verification failed: {type(exc).__name__}.",
        )
    if not integrity.intact:
        return CheckpointVerificationResult(
            CheckpointVerificationStatus.LOCAL_LEDGER_INVALID,
            "Local ledger integrity verification failed before checkpoint comparison.",
            local_sequence=0,
        )

    max_sequence = session.query(func.max(AuditRecordEntity.sequence_num)).scalar()
    local_sequence = int(max_sequence or 0)
    state = session.query(LedgerStateEntity).filter(LedgerStateEntity.singleton_id == 1).one_or_none()
    if state is not None:
        # A mismatching state is itself an integrity failure; do not let a
        # stale state make a shorter ledger appear to satisfy a checkpoint.
        state_sequence = max(0, int(state.next_sequence) - 1)
        if state_sequence != local_sequence:
            return CheckpointVerificationResult(
                CheckpointVerificationStatus.HASH_MISMATCH,
                "Persisted ledger state sequence does not match the stored ledger.",
                local_sequence=local_sequence,
            )

    if local_sequence < value.sequenceNum:
        return CheckpointVerificationResult(
            CheckpointVerificationStatus.LOCAL_LEDGER_SHORTER,
            "Local ledger is shorter than the signed checkpoint prefix.",
            local_sequence=local_sequence,
        )
    if value.sequenceNum == 0:
        if value.terminalRecordHash != GENESIS_PREV_HASH:
            return CheckpointVerificationResult(
                CheckpointVerificationStatus.HASH_MISMATCH,
                "Empty-ledger checkpoint must use the genesis terminal hash.",
                local_sequence=local_sequence,
            )
    else:
        record = session.query(AuditRecordEntity).filter(
            AuditRecordEntity.sequence_num == value.sequenceNum
        ).one_or_none()
        if record is None or record.record_hash != value.terminalRecordHash:
            return CheckpointVerificationResult(
                CheckpointVerificationStatus.HASH_MISMATCH,
                "Checkpoint terminal hash does not match the local ledger prefix.",
                local_sequence=local_sequence,
            )
    if local_sequence > value.sequenceNum:
        return CheckpointVerificationResult(
            CheckpointVerificationStatus.UNANCHORED_SUFFIX,
            "Signed checkpoint prefix matches; local ledger has an unanchored suffix.",
            prefix_matches=True,
            local_sequence=local_sequence,
        )
    return CheckpointVerificationResult(
        CheckpointVerificationStatus.MATCHING_PREFIX,
        "Signed checkpoint matches the local ledger prefix.",
        prefix_matches=True,
        local_sequence=local_sequence,
    )

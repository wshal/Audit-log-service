import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from app.checkpoint import (
    Checkpoint,
    CheckpointPayload,
    CheckpointSignatureError,
    CheckpointSigner,
    CheckpointVerificationStatus,
    canonical_checkpoint_bytes,
    verify_checkpoint_signature,
)
from app.models.schemas import AuditEventCreate
from app.services.checkpoint_verifier import verify_checkpoint_against_ledger
from app.storage.repository import AuditLedgerRepository
from app.storage.database import AuditRecordEntity, LedgerStateEntity
from app.authorization import clear_authorization_caches
from app.authorization import Principal
from tests.checkpoint_store import InMemoryCheckpointStore


AUDITOR = Principal("checkpoint-auditor", frozenset({"global_auditor"}))


def _payload(sequence: int = 1, terminal_hash: str = "a" * 64) -> CheckpointPayload:
    return CheckpointPayload(
        formatVersion=1,
        ledgerId="ledger-demo",
        protocolEpoch="v2",
        sequenceNum=sequence,
        terminalRecordHash=terminal_hash,
        checkpointCreatedAt="2026-10-12T12:00:00Z",
        checkpointKeyId="checkpoint-test-key",
    )


def test_checkpoint_serialization_is_deterministic_and_excludes_signature():
    key = Ed25519PrivateKey.generate()
    signer = CheckpointSigner("checkpoint-test-key", key)
    checkpoint = signer.sign(_payload())
    assert canonical_checkpoint_bytes(checkpoint) == canonical_checkpoint_bytes(_payload())
    assert canonical_checkpoint_bytes(checkpoint).decode() == (
        '{"checkpointCreatedAt":"2026-10-12T12:00:00Z",'
        '"checkpointKeyId":"checkpoint-test-key","formatVersion":1,'
        '"ledgerId":"ledger-demo","protocolEpoch":"v2","sequenceNum":1,'
        '"terminalRecordHash":"' + "a" * 64 + '"}'
    )
    assert b"signature" not in canonical_checkpoint_bytes(checkpoint)
    assert Checkpoint.model_validate(checkpoint.model_dump()) == checkpoint


def test_checkpoint_signature_uses_separate_trusted_key_ring():
    key = Ed25519PrivateKey.generate()
    signer = CheckpointSigner("checkpoint-test-key", key)
    checkpoint = signer.sign(_payload())
    verify_checkpoint_signature(checkpoint, {signer.key_id: signer.public_key_b64})
    with pytest.raises(CheckpointSignatureError):
        verify_checkpoint_signature(checkpoint, {"other-key": signer.public_key_b64})
    with pytest.raises(CheckpointSignatureError):
        verify_checkpoint_signature(checkpoint, {signer.key_id: CheckpointSigner("other", Ed25519PrivateKey.generate()).public_key_b64})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("formatVersion", 2),
        ("sequenceNum", -1),
        ("sequenceNum", 2_147_483_648),
        ("terminalRecordHash", "not-a-digest"),
        ("checkpointCreatedAt", "2026-10-12T12:00:00+00:00"),
        ("checkpointKeyId", ""),
    ],
)
def test_checkpoint_rejects_unsupported_or_malformed_fields(field, value):
    values = _payload().model_dump()
    values[field] = value
    with pytest.raises(ValidationError):
        CheckpointPayload.model_validate(values)


def test_checkpoint_rejects_unknown_fields_and_bad_signature():
    values = _payload().model_dump()
    values["unexpected"] = True
    with pytest.raises(ValidationError):
        CheckpointPayload.model_validate(values)
    with pytest.raises(ValidationError):
        Checkpoint(**_payload().model_dump(), signature="bad")


def test_test_only_store_does_not_allow_checkpoint_rollback():
    store = InMemoryCheckpointStore()
    key = Ed25519PrivateKey.generate()
    signer = CheckpointSigner("checkpoint-test-key", key)
    store.put(signer.sign(_payload(2, "b" * 64)))
    with pytest.raises(ValueError):
        store.put(signer.sign(_payload(1)))


def test_checkpoint_verifier_reports_no_checkpoint(db_session):
    result = verify_checkpoint_against_ledger(
        db_session, None, expected_ledger_id="ledger-demo", trusted_public_keys={}, integrity_principal=AUDITOR
    )
    assert result.status is CheckpointVerificationStatus.NO_CHECKPOINT


def test_checkpoint_verifier_matches_prefix_and_reports_unanchored_suffix(db_session):
    owner = Principal("actor-a", frozenset({"writer"}), "cred-a", (), False, True)
    repo = AuditLedgerRepository(db_session)
    first = repo.append_event(
        AuditEventCreate(eventType="TEST", actorId="actor-a", resourceType="CLIENT", resourceId="c1", payload={"n": 1}, timestamp="2026-01-01T00:00:00Z"), owner
    )
    key = Ed25519PrivateKey.generate()
    signer = CheckpointSigner("checkpoint-test-key", key)
    checkpoint = signer.sign(_payload(first.sequence_num, first.record_hash))
    trusted = {signer.key_id: signer.public_key_b64}
    assert verify_checkpoint_against_ledger(db_session, checkpoint, expected_ledger_id="ledger-demo", trusted_public_keys=trusted, integrity_principal=AUDITOR).status is CheckpointVerificationStatus.MATCHING_PREFIX
    db_session.rollback()
    second = repo.append_event(
        AuditEventCreate(eventType="TEST", actorId="actor-a", resourceType="CLIENT", resourceId="c2", payload={"n": 2}, timestamp="2026-01-01T00:00:01Z"), owner
    )
    assert second.sequence_num == 2
    result = verify_checkpoint_against_ledger(db_session, checkpoint, expected_ledger_id="ledger-demo", trusted_public_keys=trusted, integrity_principal=AUDITOR)
    assert result.status is CheckpointVerificationStatus.UNANCHORED_SUFFIX
    assert result.prefix_matches is True


def test_checkpoint_verifier_distinguishes_identity_signature_and_hash_failures(db_session):
    owner = Principal("actor-a", frozenset({"writer"}), "cred-a", (), False, True)
    record = AuditLedgerRepository(db_session).append_event(
        AuditEventCreate(eventType="TEST", actorId="actor-a", resourceType="CLIENT", resourceId="c1", payload={}, timestamp="2026-01-01T00:00:00Z"), owner
    )
    signer = CheckpointSigner("checkpoint-test-key", Ed25519PrivateKey.generate())
    checkpoint = signer.sign(_payload(record.sequence_num, record.record_hash))
    trusted = {signer.key_id: signer.public_key_b64}
    assert verify_checkpoint_against_ledger(db_session, checkpoint, expected_ledger_id="other-ledger", trusted_public_keys=trusted, integrity_principal=AUDITOR).status is CheckpointVerificationStatus.IDENTITY_MISMATCH
    tampered = checkpoint.model_copy(update={"terminalRecordHash": "f" * 64})
    assert verify_checkpoint_against_ledger(db_session, tampered, expected_ledger_id="ledger-demo", trusted_public_keys=trusted, integrity_principal=AUDITOR).status is CheckpointVerificationStatus.INVALID_SIGNATURE
    forged = signer.sign(_payload(record.sequence_num, "f" * 64))
    assert verify_checkpoint_against_ledger(db_session, forged, expected_ledger_id="ledger-demo", trusted_public_keys=trusted, integrity_principal=AUDITOR).status is CheckpointVerificationStatus.HASH_MISMATCH


def test_checkpoint_verifier_reports_shorter_local_ledger(db_session):
    db_session.add(LedgerStateEntity(singleton_id=1, next_sequence=1, tip_hash="0" * 64, state_version=1))
    db_session.commit()
    signer = CheckpointSigner("checkpoint-test-key", Ed25519PrivateKey.generate())
    checkpoint = signer.sign(_payload(1, "a" * 64))
    result = verify_checkpoint_against_ledger(
        db_session, checkpoint, expected_ledger_id="ledger-demo", trusted_public_keys={signer.key_id: signer.public_key_b64}, integrity_principal=AUDITOR
    )
    assert result.status is CheckpointVerificationStatus.LOCAL_LEDGER_SHORTER


def _append_two_records(db_session):
    owner = Principal("actor-a", frozenset({"writer"}), "cred-a", (), False, True)
    repo = AuditLedgerRepository(db_session)
    first = repo.append_event(
        AuditEventCreate(eventType="TEST", actorId="actor-a", resourceType="CLIENT", resourceId="c1", payload={"n": 1}, timestamp="2026-01-01T00:00:00Z"), owner
    )
    second = repo.append_event(
        AuditEventCreate(eventType="TEST", actorId="actor-a", resourceType="CLIENT", resourceId="c2", payload={"n": 2}, timestamp="2026-01-01T00:00:01Z"), owner
    )
    return first, second


def test_checkpoint_rejects_tampered_earlier_signature(db_session):
    first, second = _append_two_records(db_session)
    signer = CheckpointSigner("checkpoint-test-key", Ed25519PrivateKey.generate())
    checkpoint = signer.sign(_payload(second.sequence_num, second.record_hash))
    first.record_signature = "A" * 88
    db_session.commit()
    result = verify_checkpoint_against_ledger(
        db_session, checkpoint, expected_ledger_id="ledger-demo",
        trusted_public_keys={signer.key_id: signer.public_key_b64}, integrity_principal=AUDITOR,
    )
    assert result.status is CheckpointVerificationStatus.LOCAL_LEDGER_INVALID

def test_checkpoint_rejects_broken_chain_and_missing_state(db_session):
    first, second = _append_two_records(db_session)
    signer = CheckpointSigner("checkpoint-test-key", Ed25519PrivateKey.generate())
    checkpoint = signer.sign(_payload(second.sequence_num, second.record_hash))
    second.prev_hash = "f" * 64
    db_session.commit()
    result = verify_checkpoint_against_ledger(
        db_session, checkpoint, expected_ledger_id="ledger-demo",
        trusted_public_keys={signer.key_id: signer.public_key_b64}, integrity_principal=AUDITOR,
    )
    assert result.status is CheckpointVerificationStatus.LOCAL_LEDGER_INVALID

    db_session.rollback()
    db_session.query(AuditRecordEntity).filter(AuditRecordEntity.id == second.id).update({"prev_hash": first.record_hash})
    db_session.query(LedgerStateEntity).delete()
    db_session.commit()
    result = verify_checkpoint_against_ledger(
        db_session, checkpoint, expected_ledger_id="ledger-demo",
        trusted_public_keys={signer.key_id: signer.public_key_b64}, integrity_principal=AUDITOR,
    )
    assert result.status is CheckpointVerificationStatus.LOCAL_LEDGER_INVALID


def test_invalid_suffix_does_not_look_like_unanchored_suffix(db_session):
    first, second = _append_two_records(db_session)
    signer = CheckpointSigner("checkpoint-test-key", Ed25519PrivateKey.generate())
    checkpoint = signer.sign(_payload(first.sequence_num, first.record_hash))
    second.record_signature = "A" * 88
    db_session.commit()
    result = verify_checkpoint_against_ledger(
        db_session, checkpoint, expected_ledger_id="ledger-demo",
        trusted_public_keys={signer.key_id: signer.public_key_b64}, integrity_principal=AUDITOR,
    )
    assert result.status is CheckpointVerificationStatus.LOCAL_LEDGER_INVALID


def test_checkpoint_requires_explicit_integrity_principal(db_session):
    first, _ = _append_two_records(db_session)
    signer = CheckpointSigner("checkpoint-test-key", Ed25519PrivateKey.generate())
    checkpoint = signer.sign(_payload(first.sequence_num, first.record_hash))
    result = verify_checkpoint_against_ledger(
        db_session, checkpoint, expected_ledger_id="ledger-demo",
        trusted_public_keys={signer.key_id: signer.public_key_b64},
    )
    assert result.status is CheckpointVerificationStatus.LOCAL_LEDGER_INVALID


def test_checkpoint_rejects_invalid_v1_v2_transition_evidence(db_session, monkeypatch):
    monkeypatch.setenv("AUDIT_RESOURCE_OWNERSHIP", '{"CLIENT:c2":"tenant-a"}')
    clear_authorization_caches()
    legacy_owner = Principal("legacy", frozenset({"writer"}), "legacy", (), False, True)
    repo = AuditLedgerRepository(db_session)
    repo.append_event(
        AuditEventCreate(eventType="LEGACY", actorId="legacy", resourceType="CLIENT", resourceId="legacy", payload={}, timestamp="2026-01-01T00:00:00Z"), legacy_owner
    )
    tenant_owner = Principal(
        "actor-a", frozenset({"writer"}), "cred-a",
        ({"tenantId": "tenant-a", "actions": ["write"], "resourceScopes": [{"resourceType": "CLIENT", "resourceIds": ["c2"]}]},),
    )
    second = repo.append_event(
        AuditEventCreate(eventType="TEST", actorId="actor-a", resourceType="CLIENT", resourceId="c2", tenantId="tenant-a", payload={}, timestamp="2026-01-01T00:00:01Z"), tenant_owner
    )
    from app.storage.database import AuditEpochTransitionEntity
    transition = db_session.query(AuditEpochTransitionEntity).first()
    signer = CheckpointSigner("checkpoint-test-key", Ed25519PrivateKey.generate())
    checkpoint = signer.sign(_payload(second.sequence_num, second.record_hash))
    transition.transition_signature = "A" * 88
    db_session.commit()
    result = verify_checkpoint_against_ledger(
        db_session, checkpoint, expected_ledger_id="ledger-demo",
        trusted_public_keys={signer.key_id: signer.public_key_b64}, integrity_principal=AUDITOR,
    )
    assert result.status is CheckpointVerificationStatus.LOCAL_LEDGER_INVALID

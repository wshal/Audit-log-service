"""Versioned, externally anchored ledger checkpoint primitives.

This module deliberately does not publish, persist, or schedule checkpoints.  It
only defines the signed object and verification semantics used by the local
test-only checkpoint store.  Checkpoint serialization is a versioned use of the
project's deterministic Python ``json.dumps`` representation; it is not an
RFC 8785 implementation and does not alter record canonicalization.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator


_UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class CheckpointPayload(BaseModel):
    """Unsigned fields covered by a checkpoint signature."""

    model_config = ConfigDict(extra="forbid", strict=True)

    formatVersion: StrictInt = Field(..., ge=1)
    ledgerId: StrictStr
    protocolEpoch: StrictStr
    # Match the signed database INTEGER range while permitting the explicit
    # genesis checkpoint at sequence zero.
    sequenceNum: StrictInt = Field(..., ge=0, le=2_147_483_647)
    terminalRecordHash: StrictStr
    checkpointCreatedAt: StrictStr
    checkpointKeyId: StrictStr

    @field_validator("formatVersion")
    @classmethod
    def supported_format(cls, value: int) -> int:
        if value != 1:
            raise ValueError("unsupported checkpoint formatVersion")
        return value

    @field_validator("ledgerId", "protocolEpoch", "checkpointKeyId")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("checkpoint identifiers must be bounded ASCII identifiers")
        return value

    @field_validator("terminalRecordHash")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if not _HEX_DIGEST.fullmatch(value):
            raise ValueError("terminalRecordHash must be a 64-character lowercase SHA-256 digest")
        return value

    @field_validator("checkpointCreatedAt")
    @classmethod
    def validate_timestamp(cls, value: str) -> str:
        if not _UTC_TIMESTAMP.fullmatch(value):
            raise ValueError("checkpointCreatedAt must be an explicit UTC timestamp ending in Z")
        # fromisoformat catches impossible calendar or clock values.
        from datetime import datetime
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value

    def signing_dict(self) -> dict[str, Any]:
        # Use the contract field set explicitly so a signed ``Checkpoint``
        # subclass can never accidentally include its signature in signed bytes.
        return {
            name: getattr(self, name)
            for name in (
                "formatVersion", "ledgerId", "protocolEpoch", "sequenceNum",
                "terminalRecordHash", "checkpointCreatedAt", "checkpointKeyId",
            )
        }

    def signing_bytes(self) -> bytes:
        return _checkpoint_json(self.signing_dict()).encode("utf-8")


class Checkpoint(CheckpointPayload):
    """A version-1 signed checkpoint object."""

    signature: StrictStr

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("signature must be strict base64") from exc
        if len(decoded) != 64:
            raise ValueError("signature must contain one Ed25519 signature")
        return value


def _checkpoint_json(value: Mapping[str, Any]) -> str:
    """Serialize checkpoint fields with the explicitly versioned project format."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def canonical_checkpoint_bytes(checkpoint: Checkpoint | CheckpointPayload) -> bytes:
    """Return deterministic bytes for all signed fields, excluding ``signature``."""
    payload = checkpoint if isinstance(checkpoint, CheckpointPayload) else CheckpointPayload.model_validate(checkpoint.model_dump())
    return payload.signing_bytes()


class CheckpointSignatureError(ValueError):
    """Raised when a checkpoint cannot be authenticated by trusted key material."""


class CheckpointSigner:
    """Separate checkpoint signer; it never reads the application record key."""

    def __init__(self, key_id: str, private_key: Ed25519PrivateKey):
        if not _IDENTIFIER.fullmatch(key_id):
            raise ValueError("checkpoint key id is invalid")
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("private_key must be an Ed25519PrivateKey")
        self.key_id = key_id
        self._private_key = private_key

    def sign(self, payload: CheckpointPayload) -> Checkpoint:
        if payload.checkpointKeyId != self.key_id:
            raise ValueError("payload checkpointKeyId does not match signer key id")
        signature = base64.b64encode(self._private_key.sign(payload.signing_bytes())).decode("ascii")
        return Checkpoint(**payload.model_dump(), signature=signature)

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(
            self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode("ascii")


def verify_checkpoint_signature(
    checkpoint: Checkpoint,
    trusted_public_keys: Mapping[str, str | Ed25519PublicKey],
) -> None:
    """Verify a checkpoint against independently supplied trusted public keys."""
    trusted = trusted_public_keys.get(checkpoint.checkpointKeyId)
    if trusted is None:
        raise CheckpointSignatureError("checkpoint signing key is not trusted")
    try:
        public_key = (
            trusted if isinstance(trusted, Ed25519PublicKey)
            else Ed25519PublicKey.from_public_bytes(base64.b64decode(trusted, validate=True))
        )
        public_key.verify(base64.b64decode(checkpoint.signature, validate=True), checkpoint.signing_bytes())
    except Exception as exc:
        raise CheckpointSignatureError("checkpoint signature is invalid") from exc


class CheckpointVerificationStatus(str, Enum):
    NO_CHECKPOINT = "no_checkpoint"
    MATCHING_PREFIX = "matching_prefix"
    LOCAL_LEDGER_SHORTER = "local_ledger_shorter"
    HASH_MISMATCH = "hash_mismatch"
    UNANCHORED_SUFFIX = "unanchored_suffix"
    IDENTITY_MISMATCH = "identity_mismatch"
    INVALID_SIGNATURE = "invalid_signature"
    MALFORMED = "malformed"
    LOCAL_LEDGER_INVALID = "local_ledger_invalid"


@dataclass(frozen=True)
class CheckpointVerificationResult:
    status: CheckpointVerificationStatus
    details: str
    prefix_matches: bool = False
    local_sequence: int | None = None


def checkpoint_payload_from_mapping(value: Mapping[str, Any]) -> CheckpointPayload:
    """Validate unsigned checkpoint input without accepting a caller signature."""
    return CheckpointPayload.model_validate(value)

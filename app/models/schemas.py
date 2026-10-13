"""
Domain schemas and Pydantic validation models for the Audit Log Service.
"""

from datetime import datetime, timezone
import json
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator

MAX_QUERY_OFFSET = 100_000


def normalize_iso8601(value: str) -> str:
    """Parse an ISO-8601 instant and return one canonical UTC representation."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a UTC offset or 'Z'")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str) -> datetime:
    """Parse a stored or query timestamp as a timezone-aware UTC instant."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a UTC offset or 'Z'")
    return parsed.astimezone(timezone.utc)


def strict_json_loads(value: str) -> Any:
    """Parse JSON while rejecting Python's non-standard NaN/Infinity constants."""
    def reject_constant(token: str):
        raise ValueError(f"non-finite JSON constant is not permitted: {token}")
    return json.loads(value, parse_constant=reject_constant)


def _canonical_json(value: Any) -> str:
    def validate(item: Any) -> None:
        import math
        if isinstance(item, bool) or item is None or isinstance(item, (str, int)):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("Payload must contain only finite JSON numbers")
            return
        if isinstance(item, dict):
            for child in item.values():
                validate(child)
            return
        if isinstance(item, list):
            for child in item:
                validate(child)
            return
        raise ValueError("Payload contains an unsupported JSON value")
    validate(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


class AuditEventCreate(BaseModel):
    """
    Schema for appending an audit event (Scenario A Write API).
    """
    eventType: str = Field(..., min_length=1, max_length=128, description="Action or event type, e.g. USER_LOGIN, RECORD_UPDATED")
    actorId: str = Field(..., min_length=1, max_length=128, description="Identifier of actor initiating action")
    resourceType: str = Field(..., min_length=1, max_length=128, description="Type of resource accessed or modified")
    resourceId: str = Field(..., min_length=1, max_length=256, description="Unique identifier of resource")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Structured event payload")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        description="ISO-8601 timestamp. If omitted, server assigns authoritative UTC timestamp.",
    )
    tenantId: Optional[str] = Field(default=None, min_length=1, max_length=128)
    impersonatedActorId: Optional[str] = Field(default=None, min_length=1, max_length=128)
    delegationReason: Optional[str] = Field(default=None, max_length=512)

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        if not v.strip():
            return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        try:
            return normalize_iso8601(v)
        except Exception:
            raise ValueError("Timestamp must be valid ISO-8601 format (e.g. 2026-10-07T10:00:00Z)")

    @field_validator("payload")
    @classmethod
    def validate_payload_size_and_depth(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        if len(_canonical_json(value).encode("utf-8")) > 65_536:
            raise ValueError("Payload must not exceed 64 KiB when serialized")

        def depth(item: Any, level: int = 0) -> int:
            if isinstance(item, dict):
                return max((depth(child, level + 1) for child in item.values()), default=level)
            if isinstance(item, list):
                return max((depth(child, level + 1) for child in item), default=level)
            return level

        if depth(value) > 10:
            raise ValueError("Payload nesting must not exceed 10 levels")
        return value


class AuditRecordRead(BaseModel):
    """
    Immutable audit record stored and returned by query API.
    """
    id: int = Field(..., description="Internal surrogate ID")
    sequenceNum: int = Field(..., description="Sequential chain index starting at 1")
    eventType: str
    actorId: str
    resourceType: str
    resourceId: str
    payload: Dict[str, Any]
    timestamp: str
    contentHash: str = Field(..., description="SHA-256 hash of event content fields")
    prevHash: str = Field(..., description="SHA-256 hash of previous audit record in chain")
    recordHash: str = Field(..., description="SHA-256 hash binding sequence, contentHash, and prevHash")
    recordSignature: Optional[str] = Field(default=None, description="Base64 Ed25519 signature over recordHash")
    signingKeyId: Optional[str] = Field(default=None, description="Identifier of the record signing key")
    isArchived: bool = Field(default=False, description="Flag for retention policy archival (Scenario B)")
    archivedAt: Optional[str] = Field(default=None, description="Timestamp of archival")
    redactionMetadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Field-level redaction commitments and proofs (Scenario B)"
    )
    tenantId: Optional[str] = None
    authenticatedSubject: Optional[str] = None
    credentialId: Optional[str] = None
    attributionMode: Optional[str] = None
    protocolVersion: int = 1

    model_config = {"from_attributes": True}


class QueryFilters(BaseModel):
    """
    Query filters for audit records (Scenario A Query API).
    """
    actorId: Optional[str] = Field(default=None, max_length=128)
    resourceType: Optional[str] = Field(default=None, max_length=128)
    resourceId: Optional[str] = Field(default=None, max_length=256)
    eventType: Optional[str] = Field(default=None, max_length=128)
    fromTime: Optional[str] = Field(default=None, max_length=64)
    toTime: Optional[str] = Field(default=None, max_length=64)
    limit: int = Field(default=50, ge=1, le=1000)
    offset: int = Field(default=0, ge=0, le=MAX_QUERY_OFFSET)

    @field_validator("fromTime", "toTime")
    @classmethod
    def validate_query_timestamp(cls, v: Optional[str]) -> Optional[str]:
        return normalize_iso8601(v) if v else v

    @model_validator(mode="after")
    def validate_time_range(self):
        if self.fromTime and self.toTime and self.fromTime > self.toTime:
            raise ValueError("fromTime must not be later than toTime")
        return self


class PaginatedAuditResponse(BaseModel):
    """
    Paginated response container.
    """
    total: int
    limit: int
    offset: int
    items: List[AuditRecordRead]


class ViolationType(str, Enum):
    NONE = "NONE"
    CONTENT_HASH_MISMATCH = "CONTENT_HASH_MISMATCH"
    CHAIN_LINK_BROKEN = "CHAIN_LINK_BROKEN"
    SEQUENCE_DISCONTINUITY = "SEQUENCE_DISCONTINUITY"
    GENESIS_MISMATCH = "GENESIS_MISMATCH"
    RECORD_HASH_MISMATCH = "RECORD_HASH_MISMATCH"
    UNAUTHORIZED_ARCHIVAL = "UNAUTHORIZED_ARCHIVAL"
    MALFORMED_RECORD = "MALFORMED_RECORD"
    SIGNATURE_MISMATCH = "SIGNATURE_MISMATCH"


class VerificationResult(BaseModel):
    """
    Result returned by GET /audit/verify (Scenario A Chain Verification Endpoint).
    """
    intact: bool = Field(..., description="Whether the full hash chain is intact")
    recordsVerified: int = Field(..., description="Total number of records verified")
    firstBrokenSequence: Optional[int] = Field(
        default=None,
        description="Sequence number of the first compromised record, if broken"
    )
    firstBrokenRecordId: Optional[int] = Field(
        default=None,
        description="Database ID of the compromised record, if broken"
    )
    violationType: ViolationType = Field(
        default=ViolationType.NONE,
        description="Type of violation detected"
    )
    details: Optional[str] = Field(default=None, description="Detailed explanation of the discrepancy")
    verifiedAt: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC timestamp of verification check"
    )

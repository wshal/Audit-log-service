"""
Domain schemas and Pydantic validation models for the Audit Log Service.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class AuditEventCreate(BaseModel):
    """
    Schema for appending an audit event (Scenario A Write API).
    """
    eventType: str = Field(..., description="Action or event type, e.g. USER_LOGIN, RECORD_UPDATED")
    actorId: str = Field(..., description="Identifier of actor initiating action")
    resourceType: str = Field(..., description="Type of resource accessed or modified")
    resourceId: str = Field(..., description="Unique identifier of resource")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Structured event payload")
    timestamp: Optional[str] = Field(
        default=None,
        description="ISO-8601 timestamp. If omitted, server assigns authoritative UTC timestamp.",
    )

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: Optional[str]) -> str:
        if v is None or not v.strip():
            return datetime.now(timezone.utc).isoformat()
        try:
            # Validate ISO format
            datetime.fromisoformat(v.replace("Z", "+00:00"))
            return v
        except Exception:
            raise ValueError("Timestamp must be valid ISO-8601 format (e.g. 2026-10-07T10:00:00Z)")


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
    isArchived: bool = Field(default=False, description="Flag for retention policy archival (Scenario B)")
    archivedAt: Optional[str] = Field(default=None, description="Timestamp of archival")
    redactionMetadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Field-level redaction commitments and proofs (Scenario B)"
    )

    model_config = {"from_attributes": True}


class QueryFilters(BaseModel):
    """
    Query filters for audit records (Scenario A Query API).
    """
    actorId: Optional[str] = None
    resourceType: Optional[str] = None
    resourceId: Optional[str] = None
    eventType: Optional[str] = None
    fromTime: Optional[str] = None
    toTime: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


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

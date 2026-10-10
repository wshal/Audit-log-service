"""
Retention, Structured Redaction, and Verifiable Export schemas (Scenario B).
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class RetentionPolicyApplyRequest(BaseModel):
    """
    Request to archive records older than a retention cutoff or window.
    """
    retentionDays: int = Field(..., gt=0, description="Age threshold in days for archival")
    reason: str = Field(default="Standard data retention policy schedule", min_length=1, max_length=256, description="Audit trail reason")
    tenantId: Optional[str] = Field(default=None, min_length=1, max_length=128)
    resourceId: Optional[str] = Field(default=None, min_length=1, max_length=256)


class RetentionPolicyResult(BaseModel):
    """
    Summary of applied retention policy.
    """
    recordsArchived: int
    retentionCutoff: str
    archivedSequenceNumbers: List[int]
    status: str = "COMPLETED"


class RedactionRequest(BaseModel):
    """
    Request to redact specific sensitive keys in a record's payload (e.g. SSN, accountNumber).
    """
    sequenceNum: int = Field(..., description="Target record sequence number")
    fieldPaths: List[str] = Field(..., min_length=1, description="List of top-level JSON payload keys to redact, e.g. ['accountNumber', 'ssn']")
    reason: str = Field(..., min_length=1, max_length=256, description="Regulatory justification, e.g. GDPR Right to be Forgotten, PII removal")

    @field_validator("fieldPaths")
    @classmethod
    def validate_unique_top_level_fields(cls, fields: List[str]) -> List[str]:
        if any(not field or "." in field for field in fields):
            raise ValueError("fieldPaths must contain non-empty top-level payload keys")
        if len(set(fields)) != len(fields):
            raise ValueError("fieldPaths must not contain duplicates")
        return fields


class RedactionResult(BaseModel):
    """
    Confirmation of structured redaction with cryptographic commitments preserved.
    """
    sequenceNum: int
    redactedFields: List[str]
    contentHashPreserved: str
    recordHashPreserved: str
    message: str


class VerifiableExportBundle(BaseModel):
    """
    Self-contained, independently verifiable export bundle.
    Contains the records, genesis proof, boundary chain hashes, and signature/verification metadata.
    """
    exportId: str
    generatedAt: str
    queryCriteria: Dict[str, Any]
    totalRecords: int
    startSequenceNum: Optional[int]
    endSequenceNum: Optional[int]
    genesisPrevHash: str
    records: List[Dict[str, Any]]
    integrityManifests: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Signed lifecycle manifests associated with exported records",
    )
    bundleIntegrityHash: str = Field(
        ...,
        description="SHA-256 hash over the canonical sequence of record hashes in the export"
    )
    signingPublicKeys: Dict[str, str] = Field(..., description="Trusted signing key-id to Base64 Ed25519 public-key map")
    verificationInstructions: str = (
        "To verify: confirm each record contentHash and recordHash, verify recordSignature using signingPublicKey, "
        "then recompute bundleIntegrityHash across record hashes. A filtered bundle does not prove chain inclusion "
        "without an external checkpoint/inclusion proof."
    )

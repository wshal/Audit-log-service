"""
Retention, Structured Redaction, and Verifiable Export schemas (Scenario B).
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RetentionPolicyApplyRequest(BaseModel):
    """
    Request to archive records older than a retention cutoff or window.
    """
    retentionDays: int = Field(..., gt=0, description="Age threshold in days for archival")
    reason: str = Field(default="Standard data retention policy schedule", description="Audit trail reason")


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
    fieldPaths: List[str] = Field(..., description="List of JSON payload keys to redact, e.g. ['accountNumber', 'ssn']")
    reason: str = Field(..., description="Regulatory justification, e.g. GDPR Right to be Forgotten, PII removal")


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
    bundleIntegrityHash: str = Field(
        ...,
        description="SHA-256 hash over the canonical sequence of record hashes in the export"
    )
    verificationInstructions: str = (
        "To verify this bundle independently: 1. Confirm each record's contentHash matches canonical content. "
        "2. Walk the chain to verify prevHash links. 3. Recompute bundleIntegrityHash across all record hashes."
    )

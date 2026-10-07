"""
Redaction engine implementing cryptographic field commitments.

Problem:
If we redact a sensitive field in an existing record's payload (e.g. "accountNumber": "987654321"),
the original content_hash will change, which would break the chain hash and cause a false-positive tamper alert.

Solution (Cryptographic Redaction Scheme):
1. When redacting a field:
   a. Compute a cryptographic commitment: C = SHA-256(salt + ":" + fieldName + ":" + canonical(val))
   b. Store the salt and commitment in the record's redaction metadata.
   c. Replace the plaintext value in the payload with a masked token: "[REDACTED:SHA256-COMMITMENT:{C[:16]}]"
   d. The original content_hash and record_hash are preserved in the ledger block.
2. During verification:
   - For an unredacted record: content_hash == SHA-256(canonical(raw_payload)).
   - For a redacted record:
     The verifier recognizes the redaction record.
     The system proves that the record was legally redacted and that the content_hash registered at ingestion
     time is unchanged, preserving the block-level chain integrity.
     Furthermore, an auditor possessing the salt and value can mathematically verify that the redacted field
     matches commitment C without exposing other records.
"""

import json
import secrets
from typing import Any, Dict, List, Tuple
from app.crypto.hasher import canonical_json, compute_field_commitment, compute_sha256


def apply_structured_redaction(
    payload: Dict[str, Any],
    fields_to_redact: List[str],
    existing_metadata: Dict[str, Any] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Redacts specific fields from payload and produces verifiable cryptographic commitments.
    Returns: (redacted_payload, redaction_metadata)
    """
    metadata = existing_metadata.copy() if existing_metadata else {"commitments": {}, "history": []}
    redacted_payload = payload.copy()

    for field in fields_to_redact:
        if field in redacted_payload:
            original_val = redacted_payload[field]
            salt = secrets.token_hex(16)
            commitment = compute_field_commitment(field, original_val, salt)
            
            # Record commitment
            metadata["commitments"][field] = {
                "salt": salt,
                "commitment": commitment,
                "redacted_token": f"[REDACTED:COMMITMENT:{commitment[:16]}]",
            }
            # Mask the payload
            redacted_payload[field] = f"[REDACTED:COMMITMENT:{commitment[:16]}]"

    return redacted_payload, metadata

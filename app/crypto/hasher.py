"""
Cryptographic module for tamper-evident audit log chaining.

Guarantees:
1. A deterministic project-specific JSON representation (sorted keys, compact delimiters, no trailing spaces).
   This is not a complete RFC 8785 / JSON Canonicalization Scheme implementation.
2. SHA-256 cryptographic hashing.
3. Salted field-level commitments for structured redaction without breaking hash chain validation.
"""

import hashlib
import json
from typing import Any, Dict

GENESIS_PREV_HASH = "0" * 64


def canonical_json(data: Any) -> str:
    """
    Produces the project's historical deterministic JSON representation:
    - Dict keys sorted lexicographically
    - No unnecessary whitespace separators (',', ':')
    - UTF-8 compatible

    Numeric serialization follows Python's ``json.dumps`` behavior. This is
    intentionally compatibility-preserving and must not be described as full
    RFC 8785 conformance without a versioned protocol migration.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_sha256(canonical_str: str) -> str:
    """Computes SHA-256 hexadecimal digest of canonical string."""
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def compute_event_content_hash(
    event_type: str,
    actor_id: str,
    resource_type: str,
    resource_id: str,
    payload: Dict[str, Any],
    timestamp: str,
    tenant_id: str | None = None,
    authenticated_subject: str | None = None,
    credential_id: str | None = None,
    attribution_mode: str | None = None,
    delegation_reason: str | None = None,
    protocol_version: int | None = None,
) -> str:
    """
    Calculates deterministic hash of the business event fields:
    H(content) = SHA-256(canonical({
        "actorId": actor_id,
        "eventType": event_type,
        "payload": payload,
        "resourceId": resource_id,
        "resourceType": resource_type,
        "timestamp": timestamp
    }))
    """
    content_dict = {
        "actorId": actor_id,
        "eventType": event_type,
        "payload": payload,
        "resourceId": resource_id,
        "resourceType": resource_type,
        "timestamp": timestamp,
    }
    if tenant_id is not None:
        content_dict["tenantId"] = tenant_id
    if protocol_version is not None and protocol_version >= 2:
        content_dict.update({
            "authenticatedSubject": authenticated_subject,
            "credentialId": credential_id,
            "attributionMode": attribution_mode,
            "delegationReason": delegation_reason,
            "protocolVersion": protocol_version,
        })
    return compute_sha256(canonical_json(content_dict))


def compute_record_chain_hash(
    sequence_num: int,
    content_hash: str,
    prev_hash: str,
) -> str:
    """
    Computes cryptographic block chain hash binding the sequence number,
    the event content hash, and the previous block's hash.
    
    H(record) = SHA-256(canonical({
        "contentHash": content_hash,
        "prevHash": prev_hash,
        "sequenceNum": sequence_num
    }))
    """
    chain_envelope = {
        "contentHash": content_hash,
        "prevHash": prev_hash,
        "sequenceNum": sequence_num,
    }
    return compute_sha256(canonical_json(chain_envelope))


def compute_field_commitment(field_name: str, value: Any, salt: str) -> str:
    """
    Cryptographic commitment for individual payload fields (used in Scenario B redaction):
    Allows redacting the raw value while providing mathematical proof of the original value:
    Commitment = SHA-256(salt + ":" + field_name + ":" + canonical_json(value))
    """
    raw_str = f"{salt}:{field_name}:{canonical_json(value)}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

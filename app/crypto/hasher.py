"""
Cryptographic module for tamper-evident audit log chaining.

Guarantees:
1. RFC 8785 canonical JSON serialization (deterministic sorting, compact delimiters, no trailing spaces).
2. SHA-256 cryptographic hashing.
3. Salted field-level commitments for structured redaction without breaking hash chain validation.
"""

import hashlib
import json
from typing import Any, Dict

GENESIS_PREV_HASH = "0" * 64


def canonical_json(data: Any) -> str:
    """
    Produces deterministic, canonical JSON representation according to RFC 8785 principles:
    - Dict keys sorted lexicographically
    - No unnecessary whitespace separators (',', ':')
    - UTF-8 compatible
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

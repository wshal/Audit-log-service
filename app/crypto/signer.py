"""Ed25519 signing for records; private keys must never be stored in the ledger."""

import base64
import json
import os
from functools import lru_cache

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


@lru_cache(maxsize=1)
def _private_key() -> Ed25519PrivateKey:
    encoded = os.getenv("AUDIT_SIGNING_PRIVATE_KEY")
    if encoded:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) != 32:
            raise RuntimeError("AUDIT_SIGNING_PRIVATE_KEY must be base64-encoded 32-byte Ed25519 private key material")
        return Ed25519PrivateKey.from_private_bytes(raw)
    if os.getenv("AUDIT_ENV", "development").lower() == "production":
        raise RuntimeError("AUDIT_SIGNING_PRIVATE_KEY is required in production")
    # Intentionally ephemeral: convenient locally, but signatures cannot survive a restart.
    return Ed25519PrivateKey.generate()


def signing_key_id() -> str:
    return os.getenv("AUDIT_SIGNING_KEY_ID", "development-ephemeral")


def public_key_b64() -> str:
    raw = _private_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


@lru_cache(maxsize=1)
def public_key_ring() -> dict[str, str]:
    """Return trusted public keys by ID; retain retired keys for verification."""
    raw = os.getenv("AUDIT_SIGNING_PUBLIC_KEYS")
    if raw:
        try:
            ring = json.loads(raw)
            if not isinstance(ring, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in ring.items()):
                raise ValueError
            active_id = signing_key_id()
            if active_id not in ring or ring[active_id] != public_key_b64():
                raise RuntimeError("AUDIT_SIGNING_PUBLIC_KEYS must contain the active key ID and matching public key")
            return ring
        except (json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError("AUDIT_SIGNING_PUBLIC_KEYS must be a JSON key-id to base64-public-key mapping") from exc
    return {signing_key_id(): public_key_b64()}


def public_key_for_id(key_id: str | None) -> str | None:
    return public_key_ring().get(key_id or "")


def sign_record_hash(record_hash: str) -> str:
    return base64.b64encode(_private_key().sign(record_hash.encode("ascii"))).decode("ascii")


def verify_record_signature(record_hash: str, signature: str, public_key: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True)).verify(
            base64.b64decode(signature, validate=True), record_hash.encode("ascii")
        )
        return True
    except (ValueError, TypeError):
        return False
    except Exception:
        return False

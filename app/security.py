"""Minimal API-key authentication and role checks for the prototype."""

import json
import logging
import os
from dataclasses import dataclass
from functools import lru_cache

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from app.credential_store import CredentialAuthorityError, authenticate as authenticate_manifest

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_security_logger = logging.getLogger("audit.security")


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str]
    credential_id: str = ""
    tenant_grants: tuple[dict, ...] = ()
    legacy_access: bool = False
    # `legacy_access` is retained as a compatibility alias for the narrowly
    # scoped V1-write grant used by existing deployments.  It is not a read,
    # export, compliance, redaction, or retention grant.
    legacy_write: bool = False
    legacy_pii_reader: bool = False


@lru_cache(maxsize=1)
def _credentials() -> dict[str, Principal]:
    raw = os.getenv("AUDIT_API_KEYS")
    if raw:
        try:
            parsed = json.loads(raw)
            return {
                key: Principal(
                    value["subject"],
                    frozenset(value["roles"]),
                    value.get("credentialId", key),
                    tuple(value.get("tenantGrants", ())),
                    bool(value.get("legacyAccess", False)),
                    bool(value.get("legacyWrite", value.get("legacyAccess", False))),
                    bool(value.get("legacyPiiReader", False)),
                )
                for key, value in parsed.items()
            }
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise RuntimeError("AUDIT_API_KEYS must be JSON mapping API key to {subject, roles}") from exc
    if os.getenv("AUDIT_ENV", "development").lower() == "production":
        raise RuntimeError("AUDIT_API_KEYS is required in production")
    return {"development-only-audit-key": Principal("local-development", frozenset({"admin", "global_auditor", "reader", "writer", "exporter", "privacy_officer", "retention_admin", "compliance_reviewer", "pii_reader", "audit_proxy"}), "development", (), True, True, True)}


def authenticated_principal(api_key: str | None = Security(api_key_header)) -> Principal:
    manifest_path = os.getenv("AUDIT_CREDENTIAL_MANIFEST", "").strip()
    if manifest_path:
        try:
            matched = authenticate_manifest(api_key)
        except CredentialAuthorityError as exc:
            _security_logger.warning("authentication_authority_unavailable")
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="Authentication authority unavailable") from exc
        if matched is None:
            _security_logger.info("authentication_rejected outcome=invalid_credential")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key")
        credential_id, entry = matched
        return Principal(
            entry["subject"], frozenset(entry["roles"]), credential_id,
            tuple(entry.get("tenantGrants", ())),
            bool(entry.get("legacyAccess", False)),
            bool(entry.get("legacyWrite", entry.get("legacyAccess", False))),
            bool(entry.get("legacyPiiReader", False)),
        )
    if os.getenv("AUDIT_ENV", "development").lower() == "production":
        _security_logger.warning("authentication_authority_unavailable")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Authentication authority unavailable")
    principal = _credentials().get(api_key or "")
    if principal is None:
        _security_logger.info("authentication_rejected outcome=invalid_credential")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key")
    return principal


def require_roles(*roles: str):
    def dependency(principal: Principal = Depends(authenticated_principal)) -> Principal:
        if not principal.roles.intersection(roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role for this operation")
        return principal
    return dependency

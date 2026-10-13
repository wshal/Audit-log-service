"""Protected credential-manifest authority and operator lifecycle helpers."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class CredentialAuthorityError(RuntimeError):
    """The credential authority cannot be trusted or is unavailable."""


class CredentialAuthorityAmbiguousError(CredentialAuthorityError):
    """A manifest replacement occurred but durability could not be confirmed."""


_MAX_CREDENTIAL_ID = 128
_MAX_SUBJECT = 128
_MAX_TENANT_ID = 128
_MAX_RESOURCE_TYPE = 128
_MAX_RESOURCE_ID = 256
_MAX_ROLE_OR_ACTION = 128
_MAX_CREDENTIALS = 256
_MAX_ROLES = 16
_MAX_TENANT_GRANTS = 64
_MAX_ACTIONS = 16
_MAX_RESOURCE_SCOPES = 64
_MAX_RESOURCE_VALUES = 256
_ALLOWED_GRANT_ACTIONS = {"read", "write", "export", "compliance", "redact", "retain", "*"}


def _bounded_text(value: Any, field: str, maximum: int) -> None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise CredentialAuthorityError(f"invalid credential authority field: {field}")


def _validate_resource_values(value: Any, field: str) -> None:
    if value == "*":
        return
    if not isinstance(value, list):
        raise CredentialAuthorityError(f"invalid credential authority field: {field}")
    if len(value) > _MAX_RESOURCE_VALUES:
        raise CredentialAuthorityError(f"credential authority collection is too large: {field}")
    for item in value:
        if isinstance(item, str):
            _bounded_text(item, field, _MAX_RESOURCE_ID)
        elif isinstance(item, dict):
            _bounded_text(item.get("id"), f"{field}.id", _MAX_RESOURCE_ID)
            if "type" in item:
                _bounded_text(item["type"], f"{field}.type", _MAX_RESOURCE_TYPE)
        else:
            raise CredentialAuthorityError(f"invalid credential authority field: {field}")


def _validate_tenant_grants(grants: Any) -> None:
    if not isinstance(grants, list):
        raise CredentialAuthorityError("invalid credential authority field: tenantGrants")
    if len(grants) > _MAX_TENANT_GRANTS:
        raise CredentialAuthorityError("credential authority collection is too large: tenantGrants")
    for grant in grants:
        if not isinstance(grant, dict):
            raise CredentialAuthorityError("invalid credential authority grant")
        _bounded_text(grant.get("tenantId"), "tenantGrants.tenantId", _MAX_TENANT_ID)
        actions = grant.get("actions")
        if not isinstance(actions, list) or not actions or len(actions) > _MAX_ACTIONS or any(
            not isinstance(action, str)
            or not action
            or len(action) > _MAX_ROLE_OR_ACTION
            or action not in _ALLOWED_GRANT_ACTIONS
            for action in actions
        ):
            raise CredentialAuthorityError("invalid credential authority grant actions")
        if "resourceType" in grant:
            _bounded_text(grant["resourceType"], "tenantGrants.resourceType", _MAX_RESOURCE_TYPE)
        for key in ("resourceIds", "resources"):
            if key in grant:
                _validate_resource_values(grant[key], f"tenantGrants.{key}")
        scopes = grant.get("resourceScopes")
        if scopes is not None:
            if not isinstance(scopes, list):
                raise CredentialAuthorityError("invalid credential authority field: tenantGrants.resourceScopes")
            if len(scopes) > _MAX_RESOURCE_SCOPES:
                raise CredentialAuthorityError("credential authority collection is too large: tenantGrants.resourceScopes")
            for scope in scopes:
                if not isinstance(scope, dict):
                    raise CredentialAuthorityError("invalid credential authority resource scope")
                if "resourceType" in scope:
                    _bounded_text(scope["resourceType"], "tenantGrants.resourceScopes.resourceType", _MAX_RESOURCE_TYPE)
                if "resourceIds" not in scope and "resources" not in scope:
                    continue
                for key in ("resourceIds", "resources"):
                    if key in scope:
                        _validate_resource_values(scope[key], f"tenantGrants.resourceScopes.{key}")


def _manifest_path() -> Path | None:
    value = os.getenv("AUDIT_CREDENTIAL_MANIFEST", "").strip()
    return Path(value) if value else None


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise CredentialAuthorityError(f"invalid credential authority field: {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CredentialAuthorityError(f"invalid credential authority field: {field}") from exc
    if parsed.tzinfo is None:
        raise CredentialAuthorityError(f"invalid credential authority field: {field}")
    return parsed.astimezone(timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_manifest(document: Any) -> dict:
    if not isinstance(document, dict) or document.get("schemaVersion") != 1:
        raise CredentialAuthorityError("invalid credential authority manifest")
    version = document.get("manifestVersion")
    credentials = document.get("credentials")
    if not isinstance(version, int) or version < 1 or not isinstance(credentials, dict):
        raise CredentialAuthorityError("invalid credential authority manifest")
    if len(credentials) > _MAX_CREDENTIALS:
        raise CredentialAuthorityError("credential authority collection is too large: credentials")
    validated: dict[str, dict] = {}
    for credential_id, entry in credentials.items():
        if not isinstance(credential_id, str) or not credential_id or not isinstance(entry, dict):
            raise CredentialAuthorityError("invalid credential authority record")
        if len(credential_id) > _MAX_CREDENTIAL_ID:
            raise CredentialAuthorityError("invalid credential authority record")
        digest = entry.get("digest")
        subject = entry.get("subject")
        status = entry.get("status")
        if (not isinstance(digest, str) or len(digest) != 64
                or any(ch not in "0123456789abcdef" for ch in digest)
                or not isinstance(subject, str) or not subject or len(subject) > _MAX_SUBJECT
                or status not in {"active", "staged", "revoked", "superseded"}):
            raise CredentialAuthorityError("invalid credential authority record")
        _parse_time(entry.get("issuedAt"), "issuedAt")
        expires = _parse_time(entry.get("expiresAt"), "expiresAt")
        if (not isinstance(entry.get("roles"), list)
                or len(entry["roles"]) > _MAX_ROLES
                or not all(isinstance(role, str) for role in entry["roles"])):
            raise CredentialAuthorityError("invalid credential authority record")
        if any(not role or len(role) > _MAX_ROLE_OR_ACTION for role in entry["roles"]):
            raise CredentialAuthorityError("invalid credential authority record")
        _validate_tenant_grants(entry.get("tenantGrants", []))
        if "deliveryAcknowledged" in entry and not isinstance(entry["deliveryAcknowledged"], bool):
            raise CredentialAuthorityError("invalid credential authority record")
        # Expiry is derived from expiresAt; it is never serialized as a
        # lifecycle status. Persisted statuses remain active/staged/revoked/
        # superseded so an operator rewrite cannot poison the manifest.
        validated[credential_id] = {**entry, "status": status}
    return {"schemaVersion": 1, "manifestVersion": version, "credentials": validated}


def load_manifest() -> dict:
    path = _manifest_path()
    if path is None:
        raise CredentialAuthorityError("credential authority is not configured")
    try:
        with path.open("r", encoding="utf-8") as stream:
            return _validate_manifest(json.load(stream))
    except CredentialAuthorityError:
        raise
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise CredentialAuthorityError("credential authority is unavailable") from exc


def authenticate(token: str | None):
    if not isinstance(token, str) or not token:
        return None
    manifest = load_manifest()
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    for credential_id, entry in manifest["credentials"].items():
        if hmac.compare_digest(digest, entry["digest"]):
            if entry["status"] != "active" or _parse_time(entry["expiresAt"], "expiresAt") <= _now():
                return None
            return credential_id, entry
    return None


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def _lock_path(path: Path) -> Path:
    return path.with_name(f".{path.name}.lock")


@contextmanager
def _operator_lock(path: Path, timeout: float = 5.0):
    """Acquire a bounded cross-process lock; never delete the lock file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(_lock_path(path), "a+b")
    deadline = time.monotonic() + timeout
    acquired = False
    try:
        if os.name == "nt":
            import msvcrt
            while time.monotonic() < deadline:
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    acquired = True
                    break
                except OSError:
                    time.sleep(0.05)
        else:
            import fcntl
            while time.monotonic() < deadline:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except OSError:
                    time.sleep(0.05)
        if not acquired:
            raise CredentialAuthorityError("credential authority lock acquisition timed out")
        yield
    except CredentialAuthorityError:
        raise
    except (ImportError, OSError) as exc:
        raise CredentialAuthorityError("credential authority lock unavailable") from exc
    finally:
        if acquired:
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        handle.close()


def _durable_replace(path: Path, document: dict) -> None:
    _validate_manifest(document)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    replaced = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        replaced = True
        directory_flag = getattr(os, "O_DIRECTORY", None)
        if directory_flag is not None:
            directory_fd = os.open(str(path.parent), directory_flag)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except Exception as exc:
        if os.path.exists(temporary):
            os.unlink(temporary)
        if replaced:
            raise CredentialAuthorityAmbiguousError(
                "credential authority mutation outcome is ambiguous; inspect the manifest before retrying"
            ) from exc
        raise


def _empty_manifest() -> dict:
    return {"schemaVersion": 1, "manifestVersion": 1, "credentials": {}}


def _read_for_operator(path: Path) -> dict:
    try:
        return load_manifest()
    except CredentialAuthorityError:
        if path.exists():
            raise
        return _empty_manifest()


def _new_entry(subject: str, roles: list[str], token: str, expires_at: str, *, status: str,
               tenant_grants: list[dict] | None = None) -> dict:
    _bounded_text(subject, "subject", _MAX_SUBJECT)
    if not isinstance(roles, list) or any(not isinstance(role, str) or not role or len(role) > _MAX_ROLE_OR_ACTION for role in roles):
        raise CredentialAuthorityError("invalid credential authority roles")
    _validate_tenant_grants(tenant_grants or [])
    _parse_time(expires_at, "expiresAt")
    return {
        "subject": subject, "digest": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "status": status, "issuedAt": _now().isoformat().replace("+00:00", "Z"),
        "expiresAt": expires_at, "roles": roles, "tenantGrants": tenant_grants or [],
        "deliveryAcknowledged": False if status == "staged" else True,
    }


def provision(subject: str, roles: list[str], *, tenant_grants: list[dict] | None = None,
              expires_at: str, credential_id: str | None = None) -> str:
    path = _manifest_path()
    if path is None:
        raise CredentialAuthorityError("credential authority is not configured")
    token = generate_token()
    credential_id = credential_id or f"credential-{secrets.token_hex(8)}"
    _bounded_text(credential_id, "credentialId", _MAX_CREDENTIAL_ID)
    with _operator_lock(path):
        document = _read_for_operator(path)
        if credential_id in document["credentials"]:
            raise CredentialAuthorityError("credential identifier already exists")
        document["manifestVersion"] += 1
        document["credentials"][credential_id] = _new_entry(
            subject, roles, token, expires_at, status="active", tenant_grants=tenant_grants
        )
        try:
            _durable_replace(path, document)
        except CredentialAuthorityAmbiguousError:
            raise
        except Exception as exc:
            raise CredentialAuthorityError("credential provisioning persistence failed") from exc
    return token


def rotate(credential_id: str, subject: str, roles: list[str], *, expires_at: str,
           tenant_grants: list[dict] | None = None, replacement_id: str | None = None) -> str:
    """Stage a replacement; it cannot authenticate until acknowledged and activated."""
    path = _manifest_path()
    if path is None:
        raise CredentialAuthorityError("credential authority is not configured")
    token = generate_token()
    replacement_id = replacement_id or f"credential-{secrets.token_hex(8)}"
    _bounded_text(replacement_id, "credentialId", _MAX_CREDENTIAL_ID)
    with _operator_lock(path):
        document = load_manifest()
        old = document["credentials"].get(credential_id)
        if old is None or old["status"] != "active":
            raise CredentialAuthorityError("credential identifier is not active")
        if replacement_id in document["credentials"]:
            raise CredentialAuthorityError("replacement identifier already exists")
        document["manifestVersion"] += 1
        document["credentials"][replacement_id] = _new_entry(
            subject, roles, token, expires_at, status="staged", tenant_grants=tenant_grants
        )
        try:
            _durable_replace(path, document)
        except CredentialAuthorityAmbiguousError:
            raise
        except Exception as exc:
            raise CredentialAuthorityError("credential staging persistence failed") from exc
    return token


def acknowledge_delivery(credential_id: str) -> None:
    path = _manifest_path()
    if path is None:
        raise CredentialAuthorityError("credential authority is not configured")
    with _operator_lock(path):
        document = load_manifest()
        entry = document["credentials"].get(credential_id)
        if entry is None or entry["status"] != "staged":
            raise CredentialAuthorityError("credential is not staged")
        entry["deliveryAcknowledged"] = True
        document["manifestVersion"] += 1
        try:
            _durable_replace(path, document)
        except CredentialAuthorityAmbiguousError:
            raise
        except Exception as exc:
            raise CredentialAuthorityError("credential delivery acknowledgement persistence failed") from exc


def activate(credential_id: str) -> None:
    """Commit delivery-acknowledged activation and old-version supersession."""
    path = _manifest_path()
    if path is None:
        raise CredentialAuthorityError("credential authority is not configured")
    with _operator_lock(path):
        document = load_manifest()
        entry = document["credentials"].get(credential_id)
        if entry is None:
            raise CredentialAuthorityError("credential identifier not found")
        if entry["status"] == "active":
            return
        if entry["status"] != "staged" or not entry.get("deliveryAcknowledged", False):
            raise CredentialAuthorityError("credential delivery acknowledgement is required")
        entry["status"] = "active"
        for other_id, other in document["credentials"].items():
            if other_id != credential_id and other.get("subject") == entry.get("subject") and other.get("status") == "active":
                other["status"] = "superseded"
        document["manifestVersion"] += 1
        try:
            _durable_replace(path, document)
        except CredentialAuthorityAmbiguousError:
            raise
        except Exception as exc:
            raise CredentialAuthorityError("credential activation persistence failed") from exc


def revoke(credential_id: str) -> None:
    path = _manifest_path()
    if path is None:
        raise CredentialAuthorityError("credential authority is not configured")
    with _operator_lock(path):
        document = load_manifest()
        entry = document["credentials"].get(credential_id)
        if entry is None:
            raise CredentialAuthorityError("credential identifier not found")
        entry["status"] = "revoked"
        document["manifestVersion"] += 1
        try:
            _durable_replace(path, document)
        except CredentialAuthorityAmbiguousError:
            raise
        except Exception as exc:
            raise CredentialAuthorityError("credential revocation persistence failed") from exc

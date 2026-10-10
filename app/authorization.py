"""Central default-deny tenant and resource authorization policy."""

import json
import os
from functools import lru_cache

from fastapi import HTTPException, status

from app.security import Principal


@lru_cache(maxsize=1)
def resource_registry() -> dict[tuple[str, str], str]:
    raw = os.getenv("AUDIT_RESOURCE_OWNERSHIP", "{}")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("AUDIT_RESOURCE_OWNERSHIP must be JSON") from exc
    result = {}
    for key, value in parsed.items():
        if isinstance(value, str):
            tenant = value
        elif isinstance(value, dict):
            tenant = value.get("tenantId")
        else:
            tenant = None
        if tenant:
            if ":" in key:
                resource_type, resource_id = key.split(":", 1)
                result[(resource_type, resource_id)] = tenant
    return result


def clear_authorization_caches() -> None:
    resource_registry.cache_clear()


def deny(detail: str = "Not authorized for this resource") -> None:
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def authorize_legacy(principal: Principal, action: str) -> None:
    if not principal.legacy_access:
        deny("Legacy ledger access requires an explicit legacy grant")


def grant_allows(principal: Principal, action: str, tenant_id: str, resource_type: str | None = None,
                 resource_id: str | None = None) -> bool:
    """Return true only for an explicit tenant/action/resource grant."""
    for grant in principal.tenant_grants:
        if grant.get("tenantId") != tenant_id:
            continue
        actions = set(grant.get("actions", ()))
        if action not in actions and "*" not in actions:
            continue
        scopes = grant.get("resourceScopes") or []
        resources = grant.get("resources") or grant.get("resourceIds")
        if scopes:
            for scope in scopes:
                if scope.get("resourceType") not in (None, resource_type):
                    continue
                ids = scope.get("resourceIds") or scope.get("resources") or "*"
                if ids == "*" or resource_id in ids:
                    return True
            continue
        if not resources or resources == "*":
            return True
        if resource_id is None:
            return False
        for resource in resources:
            if isinstance(resource, str) and resource_id == resource:
                return True
            if isinstance(resource, dict) and resource.get("type", resource_type) == resource_type and resource.get("id") == resource_id:
                return True
    return False


def authorize(principal: Principal, action: str, tenant_id: str | None,
              resource_type: str | None = None, resource_id: str | None = None) -> None:
    if not tenant_id or not grant_allows(principal, action, tenant_id, resource_type, resource_id):
        deny()
    if resource_type and resource_id:
        owner = resource_registry().get((resource_type, resource_id))
        if owner is None or owner != tenant_id:
            deny("Unknown or foreign resource")


def authorize_tenant_action(principal: Principal, action: str, tenant_id: str) -> None:
    if not tenant_id or not any(
        grant.get("tenantId") == tenant_id and (action in set(grant.get("actions", ())) or "*" in set(grant.get("actions", ())))
        for grant in principal.tenant_grants
    ):
        deny()


def resolve_tenant(resource_type: str, resource_id: str) -> str | None:
    return resource_registry().get((resource_type, resource_id))


def resolve_tenant_by_id(resource_id: str) -> tuple[str, str, str] | None:
    matches = [(rtype, rid, tenant) for (rtype, rid), tenant in resource_registry().items() if rid == resource_id]
    return matches[0] if len(matches) == 1 else None

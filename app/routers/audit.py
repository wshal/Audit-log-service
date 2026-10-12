"""
API routes for Scenario A:
- POST /audit/events (Append-only write API)
- GET  /audit/events (Query API with multi-field filtering and pagination)
- GET  /audit/verify (Full ledger cryptographic chain verification)
"""

from typing import Optional
import hashlib
import re
from fastapi import APIRouter, Depends, HTTPException, Query, Response, Header, status
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.models.schemas import (
    AuditEventCreate,
    AuditRecordRead,
    PaginatedAuditResponse,
    QueryFilters,
    VerificationResult,
)
from app.services.verifier import ChainVerificationService
from app.storage.database import AuditRecordEntity, get_engine, get_session_factory
from app.storage.repository import AuditLedgerRepository, IdempotencyCommitUnknown
from app.security import Principal, require_roles
from app.security import authenticated_principal
from app.authorization import authorize, authorize_legacy, resolve_tenant, resolve_tenant_by_id
from app.rate_limit import enforce_authenticated_limit
from app.crypto.hasher import canonical_json

router = APIRouter(prefix="/audit", tags=["Audit Ledger"], dependencies=[Depends(enforce_authenticated_limit)])

# Database dependency injection
def get_db():
    from app.main import SessionLocal
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post(
    "/events",
    response_model=AuditRecordRead,
    status_code=status.HTTP_201_CREATED,
    summary="Append an immutable audit event",
    description="Appends an audit event to the append-only ledger and links it via cryptographic hash chaining.",
)
def append_audit_event(
    event_in: AuditEventCreate,
    response: Response,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    principal: Principal = Depends(require_roles("writer")),
    db: Session = Depends(get_db),
):
    tenant_id = event_in.tenantId
    if tenant_id:
        resource_tenant = resolve_tenant(event_in.resourceType, event_in.resourceId)
        if resource_tenant != tenant_id:
            raise HTTPException(status_code=403, detail="Unknown or foreign resource")
        authorize(principal, "write", tenant_id, event_in.resourceType, event_in.resourceId)
        if event_in.impersonatedActorId or event_in.actorId != principal.subject:
            if "audit_proxy" not in principal.roles or not event_in.delegationReason:
                raise HTTPException(status_code=403, detail="Explicit proxy delegation is required")
            event_in = event_in.model_copy(update={"actorId": event_in.impersonatedActorId or event_in.actorId})
    elif event_in.impersonatedActorId or event_in.actorId != principal.subject:
        if "audit_proxy" not in principal.roles or not event_in.delegationReason:
            raise HTTPException(status_code=403, detail="Explicit proxy delegation is required")
    from app.authorization import authorize_legacy
    if not tenant_id:
        authorize_legacy(principal, "write")
    repo = AuditLedgerRepository(db)
    if idempotency_key is None:
        record = repo.append_event(event_in, principal)
        return record.to_read_model()
    if not re.fullmatch(r"[A-Za-z0-9._~-]{16,128}", idempotency_key):
        raise HTTPException(status_code=400, detail="Invalid Idempotency-Key")
    if "timestamp" not in event_in.model_fields_set:
        raise HTTPException(status_code=400, detail="Idempotency-Key requires an explicit timestamp")
    fingerprint_material = {
        "eventType": event_in.eventType,
        "actorId": event_in.actorId,
        "resourceType": event_in.resourceType,
        "resourceId": event_in.resourceId,
        "payload": event_in.payload,
        "timestamp": event_in.timestamp,
        "tenantId": event_in.tenantId,
        "impersonatedActorId": event_in.impersonatedActorId,
        "delegationReason": event_in.delegationReason,
    }
    fingerprint = hashlib.sha256(canonical_json(fingerprint_material).encode("utf-8")).hexdigest()
    scope_tenant = tenant_id or "__legacy__"
    try:
        record, replayed = repo.append_event_idempotent(
            event_in,
            principal,
            scope_principal=principal.credential_id or principal.subject,
            scope_tenant=scope_tenant,
            scope_method="POST",
            scope_endpoint="/audit/events",
            idempotency_key=idempotency_key,
            request_fingerprint=fingerprint,
        )
    except IdempotencyCommitUnknown as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Append outcome is uncertain; retry with the same Idempotency-Key",
        ) from exc
    if replayed:
        response.status_code = status.HTTP_200_OK
        response.headers["Idempotent-Replay"] = "true"
    return record.to_read_model()


@router.get(
    "/events",
    response_model=PaginatedAuditResponse,
    summary="Query audit events with filtering and pagination",
    description="Retrieve immutable audit records filtered by actor, resource, eventType, and date ranges.",
)
def query_audit_events(
    actorId: Optional[str] = Query(None, description="Filter by actor identifier"),
    resourceType: Optional[str] = Query(None, description="Filter by resource type"),
    resourceId: Optional[str] = Query(None, description="Filter by resource ID"),
    tenantId: Optional[str] = Query(None, description="Tenant scope (never trusted as ownership proof)"),
    eventType: Optional[str] = Query(None, description="Filter by event type"),
    fromTime: Optional[str] = Query(None, description="ISO-8601 start timestamp"),
    toTime: Optional[str] = Query(None, description="ISO-8601 end timestamp"),
    limit: int = Query(50, ge=1, le=1000, description="Page limit"),
    offset: int = Query(0, ge=0, description="Offset index"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("reader")),
):
    try:
        filters = QueryFilters(
            actorId=actorId,
            resourceType=resourceType,
            resourceId=resourceId,
            eventType=eventType,
            fromTime=fromTime,
            toTime=toTime,
            limit=limit,
            offset=offset,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc))
    repo = AuditLedgerRepository(db)
    inferred = resolve_tenant_by_id(resourceId) if resourceId and not resourceType else None
    if inferred:
        resourceType = inferred[0]
        filters = filters.model_copy(update={"resourceType": resourceType})
    tenant_id = resolve_tenant(resourceType, resourceId) if resourceType and resourceId else (inferred[2] if inferred else tenantId)
    if tenant_id:
        authorize(principal, "read", tenant_id, resourceType, resourceId)
        records, total = repo.query_events(filters, principal=principal, tenant_id=tenant_id)
    elif principal.tenant_grants:
        # Ambiguous unrestricted list queries fail closed; this prevents counts from leaking.
        raise HTTPException(status_code=403, detail="A tenant-scoped resource filter is required")
    else:
        if "global_auditor" in principal.roles:
            authorize_legacy(principal, "read")
        else:
            # Preserve the historical role-only empty-list contract without
            # disclosing legacy rows, counts, or pagination metadata.
            return PaginatedAuditResponse(total=0, limit=limit, offset=offset, items=[])
        records, total = repo.query_events(filters, principal=principal)

    return PaginatedAuditResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=[r.to_read_model() for r in records],
    )


@router.get(
    "/verify",
    response_model=VerificationResult,
    summary="Cryptographic chain verification endpoint",
    description="Walks the full audit ledger, sequentially verifying hashes and chain linkage to detect any tampering.",
)
def verify_audit_chain(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("global_auditor")),
):
    result = ChainVerificationService.verify_ledger(db, principal=principal)
    return result

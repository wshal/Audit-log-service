"""
API routes for Scenario A:
- POST /audit/events (Append-only write API)
- GET  /audit/events (Query API with multi-field filtering and pagination)
- GET  /audit/verify (Full ledger cryptographic chain verification)
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
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
from app.storage.repository import AuditLedgerRepository
from app.security import Principal, require_roles
from app.security import authenticated_principal
from app.authorization import authorize, authorize_legacy, resolve_tenant, resolve_tenant_by_id

router = APIRouter(prefix="/audit", tags=["Audit Ledger"])

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
    record = repo.append_event(event_in, principal)
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
    tenant_id = resolve_tenant(resourceType, resourceId) if resourceType and resourceId else (inferred[2] if inferred else tenantId)
    if tenant_id:
        authorize(principal, "read", tenant_id, resourceType, resourceId)
        query = db.query(AuditRecordEntity).filter(AuditRecordEntity.tenant_id == tenant_id)
        if resourceType: query = query.filter(AuditRecordEntity.resource_type == resourceType)
        if resourceId: query = query.filter(AuditRecordEntity.resource_id == resourceId)
        if actorId: query = query.filter(AuditRecordEntity.actor_id == actorId)
        if eventType: query = query.filter(AuditRecordEntity.event_type == eventType)
        if fromTime: query = query.filter(AuditRecordEntity.timestamp >= fromTime)
        if toTime: query = query.filter(AuditRecordEntity.timestamp <= toTime)
        total = query.count()
        records = query.order_by(AuditRecordEntity.sequence_num.asc()).offset(offset).limit(limit).all()
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

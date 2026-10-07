"""
API routes for Scenario A:
- POST /audit/events (Append-only write API)
- GET  /audit/events (Query API with multi-field filtering and pagination)
- GET  /audit/verify (Full ledger cryptographic chain verification)
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
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
    db: Session = Depends(get_db),
):
    repo = AuditLedgerRepository(db)
    record = repo.append_event(event_in)
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
    eventType: Optional[str] = Query(None, description="Filter by event type"),
    fromTime: Optional[str] = Query(None, description="ISO-8601 start timestamp"),
    toTime: Optional[str] = Query(None, description="ISO-8601 end timestamp"),
    limit: int = Query(50, ge=1, le=1000, description="Page limit"),
    offset: int = Query(0, ge=0, description="Offset index"),
    db: Session = Depends(get_db),
):
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
    repo = AuditLedgerRepository(db)
    records, total = repo.query_events(filters)

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
def verify_audit_chain(db: Session = Depends(get_db)):
    result = ChainVerificationService.verify_ledger(db)
    return result

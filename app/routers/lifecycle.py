"""
API routes for Scenario B:
- POST /audit/retention/apply (Apply configurable retention policy)
- POST /audit/redact (Structured field-level redaction)
- GET  /audit/export (Verifiable bulk export for resourceId or actorId)
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.models.retention_redaction import (
    RedactionRequest,
    RedactionResult,
    RetentionPolicyApplyRequest,
    RetentionPolicyResult,
    VerifiableExportBundle,
)
from app.routers.audit import get_db
from app.services.lifecycle import LifecycleAndExportService
from app.security import Principal, require_roles
from app.authorization import authorize, authorize_legacy, authorize_tenant_action, resolve_tenant, resolve_tenant_by_id
from app.storage.database import AuditRecordEntity
from app.rate_limit import enforce_authenticated_limit

router = APIRouter(prefix="/audit", tags=["Retention & Redaction"], dependencies=[Depends(enforce_authenticated_limit)])


@router.post(
    "/retention/apply",
    response_model=RetentionPolicyResult,
    summary="Apply data retention policy",
    description="Soft-archives records older than specified retentionDays while maintaining unbroken hash chain integrity.",
)
def apply_retention_policy(
    request: RetentionPolicyApplyRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("retention_admin")),
):
    if request.tenantId:
        if not request.resourceId:
            raise HTTPException(status_code=403, detail="A resource scope is required for tenant retention")
        inferred = resolve_tenant_by_id(request.resourceId)
        if not inferred:
            raise HTTPException(status_code=403, detail="Unknown resource")
        authorize(principal, "retain", request.tenantId, inferred[0], request.resourceId)
    else:
        authorize_legacy(principal, "retain")
    return LifecycleAndExportService.apply_retention_policy(
        session=db,
        retention_days=request.retentionDays,
        reason=request.reason,
        tenant_id=request.tenantId,
        resource_id=request.resourceId,
        principal=principal,
    )


@router.post(
    "/redact",
    response_model=RedactionResult,
    summary="Structured field-level redaction",
    description="Redacts sensitive fields in payload using cryptographic commitments without invalidating chain hashes.",
)
def redact_audit_record(
    request: RedactionRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("privacy_officer")),
):
    try:
        return LifecycleAndExportService.redact_record_fields(
            session=db,
            sequence_num=request.sequenceNum,
            field_paths=request.fieldPaths,
            reason=request.reason,
            principal=principal,
        )
    except ValueError as e:
        code = status.HTTP_404_NOT_FOUND if "not found" in str(e) else status.HTTP_422_UNPROCESSABLE_CONTENT
        raise HTTPException(status_code=code, detail=str(e))


@router.get(
    "/export",
    response_model=VerifiableExportBundle,
    summary="Generate self-contained verifiable export bundle",
    description="Exports all records for actorId or resourceId packaged with boundary metadata and integrity hashes for offline verification.",
)
def export_audit_records(
    actorId: Optional[str] = Query(None, max_length=128, description="Actor identifier to export"),
    resourceId: Optional[str] = Query(None, max_length=256, description="Resource identifier to export"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("exporter")),
):
    if not actorId and not resourceId:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one of actorId or resourceId must be supplied for export",
        )
    if principal.tenant_grants:
        if not resourceId:
            raise HTTPException(status_code=403, detail="Tenant-scoped export requires a resource identifier")
        inferred = resolve_tenant_by_id(resourceId)
        if not inferred:
            raise HTTPException(status_code=403, detail="Unknown resource")
        authorize(principal, "export", inferred[2], inferred[0], resourceId)
    else:
        authorize_legacy(principal, "export")
    return LifecycleAndExportService.generate_verifiable_export(
        session=db,
        actor_id=actorId,
        resource_id=resourceId,
        include_pii="pii_reader" in principal.roles,
        principal=principal,
    )

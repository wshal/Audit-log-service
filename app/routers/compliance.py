"""
API routes for Scenario C:
- GET /audit/compliance/client-access (Regulatory client access audit report)
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.models.compliance import ComplianceAuditReport
from app.routers.audit import get_db
from app.services.compliance import ComplianceService
from app.security import Principal, require_roles

router = APIRouter(prefix="/audit/compliance", tags=["Regulatory Compliance"])


@router.get(
    "/client-access",
    response_model=ComplianceAuditReport,
    summary="Generate regulatory client account audit report",
    description="Allows regulators to audit all access to client data, inspect actor behavior, and review anomaly flags.",
)
def get_client_access_audit_report(
    clientId: str = Query(..., description="Target client account ID to audit"),
    fromTime: Optional[str] = Query(None, description="Start of regulatory audit window (ISO-8601)"),
    toTime: Optional[str] = Query(None, description="End of regulatory audit window (ISO-8601)"),
    actorId: Optional[str] = Query(None, description="Filter accesses by specific actor"),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("compliance_reviewer")),
):
    try:
        return ComplianceService.generate_client_access_audit_report(
            session=db, client_id=clientId, from_time=fromTime, to_time=toTime, actor_id=actorId,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc))

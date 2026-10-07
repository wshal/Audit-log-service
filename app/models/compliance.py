"""
Schemas for Scenario C: Regulatory Compliance Reporting.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ComplianceAccessLogFilter(BaseModel):
    clientId: str = Field(..., description="Target client account ID to audit")
    fromTime: Optional[str] = Field(None, description="Start of regulatory audit window")
    toTime: Optional[str] = Field(None, description="End of regulatory audit window")
    actorId: Optional[str] = Field(None, description="Filter accesses by specific employee or service actor")


class ActorAccessSummary(BaseModel):
    actorId: str
    accessCount: int
    firstAccess: str
    lastAccess: str
    justifications: List[str]


class ComplianceAuditReport(BaseModel):
    reportId: str
    generatedAt: str
    clientId: str
    periodStart: Optional[str]
    periodEnd: Optional[str]
    totalAccessEvents: int
    actorsInvolved: List[ActorAccessSummary]
    accessEvents: List[Dict[str, Any]]
    chainIntegrityVerified: bool
    complianceStatus: str = "COMPLIANT"
    anomaliesDetected: List[str] = []

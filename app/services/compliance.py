"""
Compliance Reporting and Anomaly Detection Engine (Scenario C).
Enables regulatory auditors to inspect client account access trails and verify ledger authenticity.
"""

import json
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.compliance import (
    ActorAccessSummary,
    ComplianceAuditReport,
)
from app.services.verifier import ChainVerificationService
from app.storage.database import AuditRecordEntity
from app.security import Principal
from app.models.schemas import normalize_iso8601
from app.runtime_state import ensure_ready

CLIENT_ACCESS_EVENT_TYPES = {
    "ACCOUNT_VIEWED", "ACCOUNT_MODIFIED", "PORTFOLIO_EXPORTED", "SSN_ACCESSED",
    "HOLDINGS_EXPORTED",
}


class ComplianceService:
    @staticmethod
    def _project_payload(payload: dict, include_pii: bool) -> dict:
        if include_pii:
            return payload
        sensitive = {"ssn", "taxid", "tax_id", "accountnumber", "account_number", "dob", "dateofbirth"}
        def project(value):
            if isinstance(value, dict):
                return {k: project(v) for k, v in value.items() if k.lower() not in sensitive}
            if isinstance(value, list):
                return [project(v) for v in value]
            return value
        return project(payload)

    @staticmethod
    def generate_client_access_audit_report(
        session: Session,
        client_id: str,
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
        actor_id: Optional[str] = None,
        include_pii: bool = False,
        principal=None,
    ) -> ComplianceAuditReport:
        """
        Extracts audit events for client data access, analyzes actor patterns,
        flags regulatory anomalies, and verifies cryptographic integrity.
        """
        ensure_ready()
        if principal is None:
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Authorization scope is required")
        if from_time:
            from_time = normalize_iso8601(from_time)
        if to_time:
            to_time = normalize_iso8601(to_time)
        if from_time and to_time and from_time > to_time:
            raise ValueError("fromTime must not be later than toTime")

        query = session.query(AuditRecordEntity).filter(
            AuditRecordEntity.resource_id == client_id,
            AuditRecordEntity.resource_type.in_(["CLIENT_ACCOUNT", "PORTFOLIO"]),
            AuditRecordEntity.event_type.in_(CLIENT_ACCESS_EVENT_TYPES),
        )

        if from_time:
            query = query.filter(AuditRecordEntity.timestamp >= from_time)
        if to_time:
            query = query.filter(AuditRecordEntity.timestamp <= to_time)
        if actor_id:
            query = query.filter(AuditRecordEntity.actor_id == actor_id)

        records = query.order_by(AuditRecordEntity.sequence_num.asc()).all()

        actor_stats = defaultdict(lambda: {"count": 0, "timestamps": [], "justifications": set()})
        anomalies = []
        event_dicts = []

        for r in records:
            payload = json.loads(r.payload_json)
            actor = r.actor_id
            actor_stats[actor]["count"] += 1
            actor_stats[actor]["timestamps"].append(r.timestamp)

            justification = payload.get("justification", "UNSPECIFIED")
            actor_stats[actor]["justifications"].add(justification)

            if justification == "UNSPECIFIED":
                anomalies.append(
                    f"Sequence #{r.sequence_num}: Access by actor '{actor}' lacks regulatory justification."
                )

            event = r.to_read_model()
            event["payload"] = ComplianceService._project_payload(event["payload"], include_pii)
            event_dicts.append(event)

        # Check for excessive access frequency anomaly (> 20 accesses by single actor)
        for actor, data in actor_stats.items():
            if data["count"] > 20:
                anomalies.append(
                    f"High-frequency access alert: Actor '{actor}' accessed client '{client_id}' {data['count']} times."
                )

        # Verify underlying chain integrity
        verification = ChainVerificationService.verify_ledger(
            session,
            principal=Principal("compliance-service", frozenset({"global_auditor"}), "internal-compliance"),
        )

        actors_summary = [
            ActorAccessSummary(
                actorId=actor,
                accessCount=data["count"],
                firstAccess=min(data["timestamps"]) if data["timestamps"] else "",
                lastAccess=max(data["timestamps"]) if data["timestamps"] else "",
                justifications=list(data["justifications"]),
            )
            for actor, data in actor_stats.items()
        ]

        now_iso = datetime.now(timezone.utc).isoformat()

        return ComplianceAuditReport(
            reportId=f"COMP-REP-{uuid.uuid4().hex[:12].upper()}",
            generatedAt=now_iso,
            clientId=client_id,
            periodStart=from_time,
            periodEnd=to_time,
            totalAccessEvents=len(records),
            actorsInvolved=actors_summary,
            accessEvents=event_dicts,
            chainIntegrityVerified=verification.intact,
            complianceStatus="COMPLIANT" if not anomalies and verification.intact else "FLAGGED_FOR_REVIEW",
            anomaliesDetected=anomalies,
        )

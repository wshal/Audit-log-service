# Scenario C — Requirement Normalization & Technical Design

## Regulatory Compliance: Audit Trail for Client Account Access

### 1. Product Requirement (Under-Specified)
> *"Regulators need to be able to audit access to client account data."*

---

### 2. Ambiguity Identification & Analysis

When receiving this statement, several critical engineering questions arise:

1. **Who constitutes a "Regulator"?**
   - Direct interactive user access vs. automated compliance export bundles.
   - What level of role-based access control (RBAC) and authorization is required?
2. **What constitutes "Access"?**
   - Read-only views vs. write/modify/delete mutations.
   - Do batch reports, background workers, or system synchronizations count as access?
3. **What is "Client Account Data"?**
   - Just balance and profile information, or also trade history, tax documents, and transaction logs?
4. **What are the Regulatory Frameworks?**
   - SEC Rule 17a-4 (Books and Records requirements).
   - FINRA Rule 4511 (Preservation of Records).
   - GDPR Article 30 / CCPA (Record of processing activities and data subject access requests).
5. **What constitutes "Auditing"?**
   - Real-time querying, automated compliance reporting, anomaly detection (e.g. unauthorized after-hours access or excessive bulk reads), or cryptographic proof of non-tampering?

---

### 3. Engineering Assumptions & Normalization

To proceed effectively while maintaining strict compliance integrity, the requirement is normalized as follows:

1. **Access Event Classification**:
   - Every read or write event where `resourceType` is `CLIENT_ACCOUNT` or `PORTFOLIO` is classified under the compliance umbrella.
   - Specific event types: `ACCOUNT_VIEWED`, `ACCOUNT_MODIFIED`, `PORTFOLIO_EXPORTED`, `SSN_ACCESSED`.
2. **Compliance Context**:
   - Access events must track actor identity, justification (e.g., `SERVICING_CALL`, `COMPLIANCE_INVESTIGATION`, `PORTFOLIO_REBALANCE`), and client identifier.
3. **Regulatory Deliverable**:
   - **Compliance Audit Reporting Endpoint**: An endpoint allowing auditors to extract an immutable, structured compliance audit report for any client account over a specified time window.
   - **Access Pattern Anomaly Detection**: Automatic flagging of suspicious access patterns (e.g., multiple accounts viewed by an employee without standard justification, or rapid sequential access).

---

### 4. Scope Boundary

| In Scope (Implemented) | Out of Scope (Documented Rationale) |
|---|---|
| Dedicated `GET /audit/compliance/client-access` query endpoint with regulatory filtering (client ID, actor, timeframe) and API-key role control. | Direct integration with enterprise SAML/OAuth SSO identity providers (the prototype uses configured API-key principals). |
| Aggregated compliance summary report with actor breakdown and access justification tracking. | Continuous Kafka streaming ingestion (the REST ledger provides equivalent durability and append-only semantics). |
| Anomaly detection for unusual bulk read frequency or missing compliance justifications. | Long-term WORM (Write Once Read Many) optical disc hardware storage drivers (handled via cloud object storage immutability policies in production). |
| Cryptographic chain validation attached to compliance reports. | |

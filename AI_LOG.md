# AI Usage and Decision Log

This document records the traceability of AI assistance throughout the development of the **Tamper-Evident Audit Log Service** in accordance with Schwab requirements (Section 0.3, 4.3, and 7).

## Principles & Quality Gates
- **Human-in-the-Loop**: All architectural boundaries, cryptographic choices, redaction designs, and test suites are directed, reviewed, and signed off by the engineer.
- **Traceability**: Decisions to accept, modify, or reject AI proposals are documented here.
- **Verification**: Claims in this log are tied to recorded automated test, compilation, diff-check, or manual-validation evidence. Static type checking is not configured and is not claimed as a completed quality gate.

---

## Log Entries

### Entry 1: Project Scaffolding & Architecture Formulation
- **Date**: 2026-10-07
- **Intent**: Define technical stack, system architecture, data model, and decomposition plan.
- **Prompt Summary**: "Analyze the Charles Schwab Audit Log Service requirements across Scenarios A, B, and C. Propose architecture, directory structure, and technical stack."
- **AI Proposal**: Recommended Python with FastAPI, Pydantic v2, SQLite/SQLAlchemy with strict deterministic canonical JSON serialization (RFC 8785) for cryptographic hashing.
- **Engineer Decision**: **Accepted with Refinements**.
  - Refined cryptographic approach: SHA-256 with explicit canonical sorting (keys sorted, no unescaped whitespaces) to eliminate serialization non-determinism across platforms.
  - Required explicit genesis block hash specification (`GENESIS_BLOCK_PREV_HASH = "0" * 64`).
  - Added dedicated redaction mechanism using HMAC / Merkle-leaf or salted field hashes so redacting a sensitive value retains mathematical proof of original integrity.

### Entry 2: Scenario A — Core Append-Only Ledger & Tamper Verification
- **Date**: 2026-10-07
- **Intent**: Implement Write API, Query API with multi-field filtering, and Chain Verification with tamper detection.
- **AI Proposal**: Implement fast sequence lookup and SHA-256 chain calculation over RFC 8785 canonical JSON. Provide `GET /audit/verify` that returns detailed violation classification.
- **Engineer Review**:
  - Validated strict append-only guarantee: no UPDATE or DELETE API routes exist.
  - Verified tamper detection by adding automated tests mutating SQLite database contents directly and confirming that `CONTENT_HASH_MISMATCH` and `SEQUENCE_DISCONTINUITY` are reliably flagged.
  - Upgraded Pydantic models to v2 `model_config` standard.
  - All tests passed (4/4).

### Entry 3: Scenario B — Retention, Structured Redaction & Verifiable Export
- **Date**: 2026-10-07
- **Intent**: Implement retention policy, structured cryptographic redaction of sensitive PII, and verifiable bulk export bundles.
- **AI Proposal**: Use salt-based cryptographic commitments for redacted fields so plaintext values are scrubbed while retaining mathematical proof and unbroken block hashes. Export bundles with bundle-level SHA-256 integrity digest.
- **Engineer Review**:
  - Validated that archived records do not trigger false-positive alerts on chain verification.
  - Confirmed redaction replaces target fields with verifiable commitment tokens without mutating historical content hashes.
  - Tested that independent third parties can verify exported bundles using only the metadata provided.
  - All Scenario B tests passed (3/3).

### Entry 4: Scenario C — Regulatory Compliance Reporting & Ambiguity Normalization
- **Date**: 2026-10-07
- **Intent**: Resolve ambiguous requirement ("Regulators need to be able to audit access to client account data") through formal requirement normalization, technical design, compliance report generation endpoint, and anomaly detection.
- **AI Proposal**: Implement automated compliance aggregation endpoint `GET /audit/compliance/client-access` with actor summary breakdown, missing justification flags, and continuous chain integrity verification. Documented ambiguities, assumptions, and scope boundary in `docs/scenario_c_normalization.md`.
- **Engineer Review**:
  - Validated ambiguity resolution: clearly identified regulatory actors, access event taxonomy, and compliance bounds.
  - Implemented regulatory anomaly detection flagging uncertified accesses or high-frequency anomalies.
  - Executed complete test suite across all scenarios: 8/8 tests passed.

### Entry 5: Post-Implementation Integrity Review and Hardening
- **Date**: 2026-10-08
- **Intent**: Review requirements and implementation boundaries, then add regression coverage for discovered failure modes.
- **AI Proposal**: Flagged that redacted records bypassed content verification and that concurrent SQLite writers could calculate the same sequence number. Proposed a chained redaction manifest, serialized SQLite writes, UTC timestamp normalization, and adversarial tests.
- **Engineer Decision**: **Accepted with explicit scope boundaries**.
  - Added a chained `AUDIT_RECORD_REDACTED` manifest binding the redacted payload and metadata, then verified subsequent mutation is detected.
  - Added `BEGIN IMMEDIATE` serialization for SQLite writes; confirmed with 24 competing writers.
  - Added timestamp/range validation and invalid-redaction handling.
  - Documented the remaining production requirements: authorization, key-managed cryptographic erasure, external signed checkpoints, and independently verifiable export inclusion proofs.
  - Validation: `\.venv\Scripts\python.exe -m pytest -q` => 12 passed.

### Entry 6: Security Boundary and Lifecycle Integrity Hardening
- **Date**: 2026-10-08
- **Intent**: Address the root causes identified in the review: unauthenticated control-plane operations, hash-chain rewrites by a database-only attacker, mutable archival state, and exports lacking lifecycle evidence.
- **AI Proposal**: Add API-key RBAC, Ed25519 signatures held outside the ledger, a rotation-safe public-key ring, signed lifecycle manifests for redaction and archival, and export witnesses.
- **Engineer Decision**: **Accepted with production configuration constraints**.
  - Added role checks to every API route and disabled wildcard credentialed CORS.
  - Signed each record and verify signatures using a key ID/public-key ring; production requires externally supplied signing material.
  - Made archival actions immutable, signed ledger events and verify their state against manifests.
  - Included associated lifecycle manifests and public verification keys in exports.
  - Added API-key, role, signature-forgery, offline-export, redaction-witness, and archival-tampering regression tests.
  - Validation: `\.venv\Scripts\python.exe -m pytest -q` => 18 passed.

### Entry 7: Independent Regression Review and Demonstration Validation
- **Date**: 2026-10-08
- **Intent**: Re-review the hardened code for defects introduced by security changes, verify all scenarios together, and provide a reproducible manual defense flow.
- **AI Proposal**: Test actor identity binding, key persistence across local restart, lifecycle/export evidence, compliance classification, and timestamp consistency.
- **Engineer Decision**: **Accepted with explicit environment boundaries**.
  - Persisted the ignored development signing key locally so a local ledger remains verifiable after restart; production still requires externally supplied key material.
  - Prevented ordinary writers from claiming another actor identity; only `admin` or `audit_proxy` may do so.
  - Restricted compliance reports to documented client-access resource/event types and validate report time ranges.
  - Normalized server-generated and lifecycle timestamps to UTC `Z`; reject duplicate/invalid redaction paths.
  - Added a full Scenario A/B/C/security workflow test and copy/paste manual-validation guide.
  - Validation: `\.venv\Scripts\python.exe -m pytest -q` => 22 passed; compilation and dependency checks passed.

### Entry 8: Tenant Isolation and Object Authorization
- **Date**: 2026-10-10
- **Intent**: Close the independent-review findings for tenant isolation, object authorization, PII exposure, lifecycle scope, V2 attribution integrity, migration safety, and V1/V2 transition evidence.
- **Prompt Summary**: "Implement the approved Phase 1B remediation on `security/tenant-authorization-p0`; write regression tests before fixes, preserve V1 hashes, enforce repository/service scope, and validate the full suite."
- **AI Proposal**: Add explicit legacy access, default-deny tenant/resource grants, service-level authorization contexts, PII projections, tenant-scoped lifecycle operations, a versioned V2 hash envelope, signed transition metadata, atomic first-V2 persistence, and migration tests.
- **Engineer Decision**: **Accepted with explicit limitations**.
  - Removed implicit `admin` authorization and added explicit legacy/global capability checks.
  - Added ordinary-principal two-tenant tests for cross-tenant reads, ungranted resources, actor spoofing, proxy attribution, verification privilege, lifecycle denial, PII projection, direct repository calls, V2 attribution tampering, transition tampering, and signing-failure rollback.
  - Added tenant/resource predicates to repository and lifecycle/service entry points; authorized redaction, export, compliance, and retention are now tested positively.
  - Bound V2 hashes to tenant ownership, authenticated subject, credential ID, attribution mode, delegation reason, and protocol version.
  - Added additive/idempotent migration coverage for existing V1 schemas; historical V1 fields and hashes are not rewritten or assigned tenants.
  - Added `docs/phase1b_v2_protocol.md` documenting the same-table/global-sequence trade-off and the remaining checkpoint limitation.
  - Validation: `\.venv\Scripts\python.exe -m pytest -q` => **33 passed**; `python -m compileall -q app tests` and `git diff --check` completed successfully.
- **Remaining limitations**: V1 and V2 still share the physical table/global sequence; valid signed tail truncation requires an independent checkpoint; nested PII classification and startup quarantine for inconsistent legacy data remain future work.

### Entry 9: Authorization, Integrity, and PII Review Follow-up
- **Date**: 2026-10-10
- **Intent**: Close the residual administrator V1-write bypass, protect direct full-ledger verification/repository access, and strengthen attribution/PII regression coverage.
- **Engineer Decision**: **Implemented Steps 1–3; Step 4 paused for policy approval**.
  - V1 append now requires explicit `legacyAccess`; administrator role alone is insufficient.
  - Direct repository full-ledger reads and verifier calls require an explicit `global_auditor` principal; compliance uses an internal verification capability rather than exposing global access to tenant callers.
  - Added positive/negative legacy-write tests, direct repository/verifier tests, parameterized V2 tampering tests for all integrity-bound fields, and recursive nested object/array PII projection tests.
  - Updated the existing writer fixture to declare explicit legacy access; no security assertion was weakened.
  - Validation so far: focused tenant tests **19 passed**; migration plus tenant tests **20 passed**; full suite **42 passed**.
- **Pending decision**: Startup behavior for inconsistent V1 data is not yet implemented. Proposed policy is fail-closed read-only quarantine with unhealthy status, no automatic repair, and operator recovery from a preserved/trusted database copy.

### Entry 10: Legacy Integrity Preflight and Quarantine
- **Date**: 2026-10-10
- **Intent**: Enforce the approved startup integrity boundary before serving audit traffic.
- **Engineer Decision**: **Implemented fail-closed quarantine**.
  - Added lifecycle states `uninitialized`, `validating`, `healthy`, and `quarantined`.
  - Schema migration completes before a read-only verifier preflight. Corrupt, malformed, invalid-transition, infrastructure, and indeterminate outcomes create a quarantine marker and block `/audit/*` routes and readiness with `503`.
  - `/health` exposes only minimal status; liveness remains available for diagnostics. Restart does not clear quarantine; recovery requires operator-approved recovery after database repair/restoration.
  - Added tests for fresh, malformed, broken-sequence, invalid-signature, valid mixed V1/V2, missing transition, quarantine persistence, and explicit recovery.
  - Validation: preflight tests **7 passed**; focused authorization tests **19 passed**; migration plus authorization tests **20 passed**; final full suite **49 passed**; compileall and `git diff --check` completed successfully.
- **Limitations**: The preflight uses the existing shared-table/global-sequence verifier and cannot detect validly signed tail truncation without an independently retained checkpoint.

### Entry 11: Quarantine and Recovery Hardening
- **Date**: 2026-10-10
- **Intent**: Close independent-review findings below the HTTP layer and remove repeatable recovery authorization.
- **Engineer Decision**: **Implemented and tested.**
  - Added shared readiness enforcement to repository, verifier, lifecycle, and compliance entry points; only the scoped startup preflight context can run while validating.
  - Replaced direct marker writes with same-directory temp-file flush/fsync/atomic-replace persistence and best-effort directory fsync.
  - Marker, session, verifier, and persistence failures remain quarantined and unready.
  - Replaced persistent recovery approval with a one-time `AUDIT_QUARANTINE_RECOVERY_TOKEN`; its hash and outcome are persisted and the marker is removed only after successful validation.
  - Added direct-entry, recovery-consumption, and restart regression coverage; preflight does not mutate historical rows.
- **Validation**: Latest recorded run: `.venv\Scripts\python.exe -m pytest -q` => **55 passed**; `python -m compileall -q app tests` and `git diff --check` completed successfully.
- **Limitations**: Marker durability is bounded by the configured local filesystem; directory fsync is best-effort where unsupported. Valid signed tail truncation still requires an independent checkpoint.

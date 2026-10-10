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

### Entry 12: Service-Boundary Authorization Remediation
- **Date**: 2026-10-10
- **Intent**: Close independently identified direct-call authorization bypasses without changing the V1/V2 integrity protocol or quarantine model.
- **Review finding**: Lifecycle retention/redaction/export, compliance reporting, and repository V1 append previously relied too heavily on router checks or only required a non-null principal.
- **Engineer Decision**: **Implemented with failing direct-call tests first.**
  - Added operation-role checks and tenant/resource ownership checks at service boundaries.
  - Required explicit PII-reader capability for raw-PII exports and compliance reports.
  - Required explicit writer role plus legacy capability for repository V1 appends; an admin role alone remains insufficient.
  - Scoped legacy exports/reports to V1 rows and tenant exports/reports to the authorized tenant/resource predicate.
  - Preserved readiness/quarantine enforcement and existing V1/V2 hashing and transition behavior.
- **Validation**: `pytest tests/test_tenant_authorization.py -q` => **22 passed**; migration plus authorization tests => **23 passed**; full suite => **58 passed**; compileall and `git diff --check` exited successfully.
- **Review state**: Changes are intentionally uncommitted pending independent review, as requested.

### Entry 13: Close the final two authorization-boundary findings
- **Date**: 2026-10-10
- **Intent**: Remove record-existence disclosure during redaction and enforce the reader role in direct repository queries.
- **Engineer Decision**: **Implemented with failing tests first.**
  - Redaction now builds a tenant/resource/legacy scope predicate before loading the target sequence and normalizes unauthorized and nonexistent targets to the same not-found result.
  - The redaction router delegates lookup and authorization to the service boundary, preventing an HTTP-layer existence distinction.
  - Repository queries now require the `reader` role in addition to tenant grants or legacy access.
  - Added regression coverage for wrong-scope existing/nonexistent redaction targets, unchanged rows/manifests, authorized redaction, tenant grants without reader role, and legacy access without reader role.
- **Validation**: Tenant tests **25 passed**; migration plus tenant tests **26 passed**; full suite **61 passed**; compileall and `git diff --check` exited successfully.
- **Review state**: Changes remain uncommitted and unpushed pending independent review.

### Entry 14: Make quarantine recovery authorization single-use across processes
- **Date**: 2026-10-10
- **Intent**: Close the recovery-token concurrency race in `_consume_recovery_token()` without changing the quarantine or integrity protocol.
- **Finding reproduced**: A barrier-controlled concurrent test demonstrated that two callers could both observe an absent reservation and both return success.
- **Engineer Decision**: **Implemented with an atomic filesystem reservation.**
  - Recovery consumption now uses exclusive `O_CREAT | O_EXCL` creation of the consumed-token record; exactly one process sharing the marker filesystem can reserve a token.
  - The reservation is retained if writing or fsyncing the outcome fails, preventing silent token reuse.
  - Plaintext tokens are never stored or logged. Marker removal still occurs only after successful integrity validation.
  - Documented the supported durability boundary: shared durable filesystem across processes; separate local/ephemeral volumes or multi-host deployments require an external lock or shared store.
  - Added concurrency, persistence-failure, repeated-use, failed-recovery, and restart regression tests.
- **Validation**: Preflight tests **16 passed**; tenant tests **25 passed**; migration plus tenant tests **26 passed**; full suite **64 passed**; compileall and `git diff --check` exited successfully.
- **Review state**: Changes remain uncommitted and unpushed pending independent review.

### Entry 15: Enforce fail-closed recovery outcome persistence
- **Date**: 2026-10-10
- **Intent**: Close the acceptance finding where missing recovery reservation state could be treated as successful recovery.
- **Engineer Decision**: **Implemented with failing regression tests first.**
  - Recovery outcome recording now requires a readable, valid reservation document and raises on missing, malformed, unreadable, or failed persistence state.
  - Outcome updates use a same-directory temporary file, flush/fsync, atomic replacement, and directory fsync where supported. Unsupported directory durability is explicitly documented.
  - Preflight cannot remove the quarantine marker unless recovery outcome persistence succeeds; marker-removal failures remain quarantined.
  - Added tests for missing/malformed/unreadable reservations, write/replace/file-fsync/directory-fsync failures, marker retention, and marker-removal failure.
- **Validation**: Focused preflight tests, tenant authorization tests, migration plus tenant tests, full suite, compileall, and `git diff --check` run after implementation; exact results are reported with this entry.
- **Remaining limitation**: Crash consistency still depends on the configured filesystem; no external checkpoint or distributed recovery store is introduced.

### Entry 16: Make recovery reservations directory-durable
- **Date**: 2026-10-10
- **Intent**: Address the acceptance finding that initial reservation creation did not flush its containing directory, and strengthen end-to-end failure evidence.
- **Engineer Decision**: **Implemented with focused regression tests.**
  - `_consume_recovery_token()` now flushes/fsyncs the reservation file and then fsyncs its containing directory where supported. Unsupported directory fsync is distinguished from genuine open/fsync failures; genuine failures propagate and remain quarantined.
  - Added full-preflight malformed and unreadable reservation tests, reservation directory-fsync success/failure tests, and subprocess interruption tests before outcome persistence and before marker removal.
  - Existing `O_CREAT | O_EXCL` semantics, outcome ordering, marker safeguards, and authorization controls are unchanged.
- **Validation**: Final command results are reported with this entry; no commit or push was performed.
- **Remaining limitation**: Crash consistency remains bounded by the configured filesystem and does not provide a distributed multi-host guarantee.

### Entry 17: Add end-to-end directory-fsync failure coverage
- **Date**: 2026-10-10
- **Intent**: Address the independent review gap requiring directory-fsync failure coverage through the complete preflight path.
- **Engineer Decision**: **Added a focused regression test without production-code changes.**
  - The test injects failure during reservation directory fsync, invokes `run_integrity_preflight()`, verifies quarantine-marker retention and quarantined health, asserts `/ready` returns 503, and confirms the consumed reservation remains non-reusable.
- **Validation**: Required focused, authorization, migration, full-suite, compileall, and diff-check commands were run after this test addition.

### Entry 18: Prompt 1 authorization evidence completion
- **Date**: 2026-10-10
- **Intent**: Close the remaining evidence gaps for export/compliance non-disclosure and direct service-boundary authorization without changing recovery, coverage, CI, or database-concurrency behavior.
- **Engineer Decision**: **Implemented with focused regression tests first.**
  - Export lifecycle-manifest retrieval now applies the authorized tenant or legacy predicate in the database query before loading manifest rows.
  - Added direct denial tests proving unauthorized retention and export leave audit state unchanged.
  - Added a two-tenant export test proving lifecycle manifests are limited to the authorized tenant/resource.
  - Added an HTTP regression test proving an ordinary writer cannot replace the authenticated actor identity.
- **Validation**: `pytest tests/test_tenant_authorization.py -q` => **30 passed**; migration plus tenant tests => **31 passed**; full suite => **86 passed**; compileall and `git diff --check` exited successfully. Each run emitted the existing Starlette/httpx deprecation warning.
- **Remaining limitation**: Coverage tooling, CI configuration, and requirements-to-test matrix work remain intentionally outside this Prompt 1-only change.

### Entry 19: Prompt 1 final authorization remediation
- **Date**: 2026-10-11
- **Intent**: Address the independent review findings for repository actor binding, explicit V1 legacy authorization, and V1 proxy/admin attribution.
- **Engineer Decision**: **Implemented at repository/service boundaries with failing tests first.**
  - Repository appends now reject actor substitution unless `audit_proxy` and a non-empty delegation reason are present.
  - Legacy reads/exports/compliance require `global_auditor`; V1 lifecycle mutation is denied; explicit legacy-write and legacy-PII capabilities are separated in principal configuration.
  - V1 router attribution no longer treats `admin` as an impersonation grant.
  - Added precise direct repository/service tests for forged actors, legacy operation denials, and V1 proxy/admin behavior.
  - Updated Scenario A/B/C and integrity fixtures to model delegated ingestion explicitly with a delegation reason; no legacy-ingestion exception or admin bypass was added.
- **Validation**: Tenant authorization tests **34 passed**; migration plus tenant tests **35 passed**; full suite **90 passed**; compileall and `git diff --check` exited successfully. Each run emitted the existing Starlette/httpx deprecation warning.
- **Status**: Prompt 1 compatibility remediation is ready for independent review; no commit or push was performed.

### Entry 20: Close legacy PII authorization evidence gap
- **Date**: 2026-10-11
- **Intent**: Add the final test-only proof that generic PII access does not authorize raw V1 PII.
- **Engineer Decision**: **Test-only change; production authorization was unchanged.**
  - Added a real V1 compliance/export regression using a global auditor with `pii_reader` but without `legacyPiiReader`; both paths return HTTP 403 before exposing payload data.
  - Verified denied requests leave payload bytes and hashes unchanged.
  - Added a positive compliance control with the explicit `legacyPiiReader` capability.
- **Validation**: Tenant tests **35 passed**; migration plus tenant tests **36 passed**; full suite **91 passed**; compileall and `git diff --check` exited successfully. The existing Starlette/httpx deprecation warning remains.
- **Status**: No production code, Prompt 2A recovery behavior, coverage configuration, or CI files were changed. No commit or push was performed.

### Entry 21: Establish reproducible coverage and CI validation
- **Date**: 2026-10-11
- **Intent**: Measure and improve test reliability, coverage evidence, and clean-checkout reproducibility without changing authorization, recovery, or database concurrency behavior.
- **Engineer Decision**: **Implemented the approved test-quality scope only.**
  - Added the declared `pytest-cov` dependency and `.coveragerc` with branch instrumentation and no broad application exclusions.
  - Added two meaningful fail-closed configuration tests for malformed API-key and resource-ownership configuration.
  - Added a maintained requirements-to-test matrix covering authorization, integrity, lifecycle, recovery, failure handling, and the SQLite-only limitation.
  - Added a minimal Windows/Python 3.12 GitHub Actions workflow running the full suite, line/branch coverage, the 85% combined gate, compile checks, and uploading `coverage.xml`.
  - Updated current test and coverage instructions while preserving historical test counts as historical records.
- **Baseline validation**: The pre-change suite had **91 passed**. Measured baseline coverage was **90.77% line**, **78.76% branch**, and **88.04% combined**.
- **Threshold rationale**: The CI gate is **85% combined coverage**, below the measured baseline to allow platform-dependent startup/error branches while preventing material regression. Branch coverage is reported separately and is not represented as PostgreSQL or distributed-system evidence.
- **Final validation**: `python -m pytest -q` => **93 passed**, one existing Starlette/httpx deprecation warning. Coverage command with line and branch instrumentation => **91.08% line**, **78.76% branch**, **88.27% combined**, and the configured **85% combined gate passed**. `python -m compileall -q app tests` and `git diff --check` both exited successfully.
- **Limitations**: Coverage and tests use isolated SQLite only; no PostgreSQL integration, distributed deployment, or Prompt 2B recovery redesign is included. GitHub Actions has not been executed in this local environment; its commands match the validated local coverage and compile commands.

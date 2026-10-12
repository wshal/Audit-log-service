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

### Entry 22: Establish versioned migrations and ledger-state schema
- **Date**: 2026-10-11
- **Intent**: Add the first database-correctness foundation without changing append allocation, retries, idempotency, authorization, or recovery behavior.
- **Engineer Decision**: **Implemented the migration/schema slice only; allocator work remains deferred.**
  - Added Alembic configuration, environment, and revision `0001_schema_foundation`.
  - Fresh databases use the versioned baseline; recognized pre-migration SQLite schemas receive additive columns/tables only.
  - Unrecognized existing schemas fail before migration state is stamped, preserving the existing database for operator review.
  - Added `ledger_state` with singleton, sequence, tip-hash, and state-version constraints. No state row is backfilled and no append path reads it yet.
  - Existing audit rows, payload bytes, hashes, signatures, sequence values, and transition evidence are not rewritten or deleted.
  - Added focused fresh-schema, repeat-migration, constraint, and incompatible-schema tests.
- **Validation**: Focused migration and legacy-compatibility tests (`.venv\\Scripts\\python -m pytest tests/test_database_migrations.py tests/test_phase1b_migration.py -q`) **8 passed**. Full suite (`.venv\\Scripts\\python -m pytest -q`) **100 passed** with the existing Starlette/httpx deprecation warning. `python -m compileall -q app tests` and `git diff --check` exited successfully. Alembic configuration warnings were removed by setting `path_separator = os`.
- **Limitations**: PostgreSQL execution is not verified because no PostgreSQL service/driver test environment is available. Unified allocator, PostgreSQL row locking, retries, and idempotency remain for later Prompt 3 stages.

### Entry 23: Close migration-safety validation gaps
- **Date**: 2026-10-11
- **Intent**: Address the independent review findings before any allocator work.
- **Changes**:
  - Added portable SQLAlchemy type-family, nullability, default, primary-key, uniqueness, and ledger-state check validation for recognized schemas.
  - Revalidated already-stamped `0001_schema_foundation` databases and rejected unknown revisions or incomplete stamped tables.
  - Rejected non-empty databases without the recognized audit baseline instead of treating them as fresh installations.
  - Added isolated tests for valid/malformed stamped schemas, unknown revisions, unknown non-empty databases, malformed intermediate columns, and retry state.
  - Extended mixed V1/V2 preservation coverage to invoke the real `ChainVerificationService` after migration.
- **Validation**: Migration and legacy regression tests **13 passed**; full suite **105 passed** with the existing Starlette/httpx deprecation warning. Compileall and `git diff --check` passed.
- **Limitations**: Validation and migration execution remain SQLite-only. PostgreSQL DDL/type reflection and concurrent allocator behavior are not claimed or tested.

### Entry 24: Complete migration-safety test evidence
- **Date**: 2026-10-11
- **Intent**: Close the remaining evidence gaps identified during independent migration review without changing allocator or concurrency behavior.
- **Changes**:
  - Extended interrupted SQLite migration coverage to inspect the actual additive column, reflected type/nullability, required tables, unstamped revision, historical integrity fields, and final retry schema.
  - Added stamped-schema tests for incorrect type, incorrect nullability, and missing ledger-state tip-hash constraint.
  - Preserved the malformed-intermediate-schema rejection test and valid stamped-schema test.
- **Validation**: Migration and legacy regression tests **16 passed**; full suite **108 passed** with the existing Starlette/httpx deprecation warning. Compileall and `git diff --check` passed.
- **Limitations**: All evidence remains SQLite-only. PostgreSQL reflection, DDL failure behavior, and PostgreSQL constraint semantics still require a real PostgreSQL environment.

### Entry 25: Activate the unified ledger-state allocator
- **Date**: 2026-10-11
- **Intent**: Introduce database-level sequence and chain-tip serialization while preserving the existing hash and event formats.
- **Changes**:
  - Added shared ledger-state locking and initialization in `AuditLedgerRepository`.
  - SQLite retains `BEGIN IMMEDIATE`; PostgreSQL uses singleton-row insertion and `FOR UPDATE` locking.
  - Normal appends and lifecycle journal appends now allocate from `ledger_state` and advance it in the same transaction.
  - Populated ledgers are derived only when sequence/previous-hash continuity is consistent; mismatches fail closed.
  - Added tests for empty and populated initialization, state mismatch rejection, failed append atomicity, state advancement, and existing concurrent writers.
- **Validation**: Full suite **114 passed** with the existing Starlette/httpx deprecation warning. Compileall and `git diff --check` passed.
- **Limitations**: PostgreSQL execution, row-lock behavior, and independent multi-instance concurrency remain unverified. Blind retries and idempotency remain deferred.

### Entry 26: Close allocator lock and state-trust review findings
- **Date**: 2026-10-11
- **Intent**: Correct the remaining Prompt 3B2 allocator issues without starting retries, idempotency, or unrelated database work.
- **Changes**:
  - Rejected allocator calls that arrive with pending ORM writes, preventing a caller from bypassing SQLite `BEGIN IMMEDIATE`; read-only inspection transactions are rolled back before lock acquisition, while callers must close any Core-SQL transaction first.
  - Added rollback/lock-marker cleanup when state validation rejects a missing or inconsistent populated ledger, preventing leaked SQLite writer locks after a failed append.
  - Removed ordinary append/lifecycle state derivation as a recovery mechanism. Populated ledgers with missing state now fail closed and require explicit startup initialization; empty ledgers may initialize the singleton state.
  - Required lifecycle journal appends to hold the shared allocator lock and to advance `ledger_state` in the same transaction.
  - Strengthened the concurrent-writer regression to assert record count, contiguous unique sequences, previous-hash links, and successful real global-ledger verification; added direct lock-boundary tests.
- **Validation**: Focused integrity/authorization tests (`.venv\\Scripts\\python -m pytest tests/test_integrity_regressions.py tests/test_tenant_authorization.py -q`) **48 passed** with the existing Starlette/httpx deprecation warning. Full suite (`.venv\\Scripts\\python -m pytest -q`) **117 passed** with the same warning. `python -m compileall -q app tests` and `git diff --check` also exited successfully.
- **Limitations**: The concurrency evidence uses threads against one SQLite file; PostgreSQL row-lock behavior and independent multi-process/multi-instance execution remain unverified. The allocator validates sequence/previous-hash state consistency, while full content/signature verification remains the explicit startup preflight responsibility. Retries and idempotency remain deferred.

### Entry 27: Enforce allocator ownership and lifecycle failure cleanup
- **Date**: 2026-10-11
- **Intent**: Resolve the independent Prompt 3B2 review findings without adding retries, idempotency, or PostgreSQL implementation.
- **Changes**:
  - Allocator acquisition now rejects every pre-existing SQLAlchemy transaction, including read-only and Core-SQL transactions, without committing or rolling it back. Callers must explicitly end caller-owned work before allocation.
  - Added lifecycle failure cleanup covering lookup, mutation, journal construction/signing, flush, and commit exceptions. A failed retention/redaction operation rolls back its transaction and clears the allocator lock marker before re-raising.
  - Constructed redaction results before commit so successful lifecycle calls do not reopen an implicit read transaction while returning expired ORM fields.
  - Added regression coverage for caller-owned ORM/Core transactions, lifecycle signing failure, rollback/state preservation, marker cleanup, and subsequent same-session reuse.
- **Validation**: Focused integrity/authorization tests **51 passed**; migration plus tenant tests **38 passed**; full suite **120 passed**, each with the existing Starlette/httpx deprecation warning. Compileall and `git diff --check` passed.
- **Limitations**: PostgreSQL execution, separate-process/multi-instance concurrency, and retry/idempotency remain unverified or deferred. The strict ownership contract requires all callers to explicitly end any transaction before append or lifecycle mutation.

### Entry 28: Complete append cleanup and fail-safe rollback handling
- **Date**: 2026-10-11
- **Intent**: Close the remaining allocator/lifecycle cleanup findings without adding retries or idempotency.
- **Changes**:
  - Added common append failure cleanup for every exception after allocator ownership, including unexpected flush and commit exceptions. Rollback is attempted, the ownership marker is always released, and rollback failure invalidates the session while preserving the original exception.
  - Lifecycle cleanup now uses the same helper, including rollback-failure invalidation; a failed session cannot perform a subsequent allocation until recreated.
  - Replaced the Core-SQL DDL fixture with a real `UPDATE ledger_state` mutation whose caller transaction remains active and caller-owned after allocator rejection.
  - Added append flush/commit failure tests, append rollback-failure tests, lifecycle flush/commit failure tests, lifecycle rollback-failure tests, and same-session stale-ownership assertions.
- **Validation**: Focused integrity/authorization tests **57 passed**; migration plus tenant tests **41 passed**; full suite **126 passed**, each with the existing Starlette/httpx deprecation warning. Compileall and `git diff --check` passed.
- **Limitations**: A database commit exception can leave the external commit outcome ambiguous; the implementation deliberately does not retry. PostgreSQL execution and independent-process/multi-instance concurrency remain unverified.

### Entry 29: Establish PostgreSQL migration integration infrastructure
- **Date**: 2026-10-11
- **Intent**: Implement Gate 1 only: provide a reproducible PostgreSQL 16 environment and verify the existing Alembic migration without changing allocator, authorization, retry, or idempotency behavior.
- **Changes**:
  - Added optional `requirements-postgres.txt` with psycopg 3.
  - Added disposable `docker-compose.postgres.yml` with health checking and ephemeral storage.
  - Added isolated `tests/postgres/` fixtures that reject non-local hosts and non-`audit_test` databases, reset only the isolated public schema, run the actual Alembic configuration, inspect PostgreSQL constraints/indexes/nullability, verify the migration head, repeatability, and empty-ledger initialization.
  - Added a GitHub Actions PostgreSQL 16 service job that waits for health, installs the optional driver, and runs the integration tests.
- **Validation**: SQLite/default validation remains unchanged. PostgreSQL integration execution depends on Docker/PostgreSQL availability and is reported separately; no PostgreSQL service was assumed or claimed to pass unless actually run.
- **Limitations**: This gate does not implement concurrent allocator tests, independent application processes, retries, idempotency keys, or PostgreSQL lifecycle/append failure testing. Those remain unverified and out of scope.

### Entry 30: Tighten PostgreSQL Gate 1 evidence
- **Date**: 2026-10-11
- **Intent**: Address the independent Gate 1 review findings without changing production allocator or authorization behavior.
- **Changes**:
  - Restricted the PostgreSQL test URL guard to the declared `postgresql+psycopg` driver and added URL-only tests for accepted, unsupported, non-local, and non-test targets.
  - Changed the integration engine fixture to reset the guarded `audit_test` schema per test.
  - Added direct PostgreSQL DML assertions for singleton, duplicate singleton, sequence, tip-hash, state-version, and audit-record sequence uniqueness constraints.
- **Validation**: PostgreSQL URL tests passed; PostgreSQL integration tests collected **6 passed, 4 skipped** because Docker/PostgreSQL is unavailable locally. The full default suite completed with **132 passed, 4 skipped** and the existing Starlette/httpx deprecation warning. Compileall and `git diff --check` exited successfully; no PostgreSQL execution is claimed.
- **Limitations**: Runtime PostgreSQL migration and constraint enforcement remain unverified until Docker or a real PostgreSQL service is available. Concurrent PostgreSQL allocator behavior remains out of scope.

### Entry 31: Add PostgreSQL concurrency and transaction correctness evidence
- **Date**: 2026-10-11
- **Intent**: Implement Gate 2 tests using the existing database allocator and transaction boundaries, without adding retries, idempotency, or an alternate allocation path.
- **Changes**:
  - Added bounded independent-process PostgreSQL append coverage asserting serialized contiguous sequences, consistent previous-hash links, and final ledger-state tip/sequence values.
  - Added PostgreSQL append flush-failure coverage proving rollback and same-session reuse.
  - Added PostgreSQL lifecycle journal failure coverage with a persisted before/after snapshot of records, integrity/attribution fields, transitions, archive metadata, and ledger state; the same session remains reusable afterward.
  - Documented the Gate 2 scope and its real-PostgreSQL execution boundary.
- **Validation**: `tests/postgres` collected **6 passed, 7 skipped** locally; the seven database-backed tests were skipped because Docker/PostgreSQL is unavailable. The full suite completed with **132 passed, 7 skipped** and the existing Starlette/httpx deprecation warning. Compileall and `git diff --check` passed.
- **Limitations**: PostgreSQL concurrency and transaction behavior remain unverified locally and must execute in CI against PostgreSQL 16. Worker cleanup is bounded and forcibly terminates any process still alive after the cleanup deadline; this is test-process containment, not a production recovery guarantee. Commit-outcome recovery, retries, idempotency, and multi-host storage behavior remain outside this gate.

### Entry 32: Enforce PostgreSQL worker exit-status validation
- **Date**: 2026-10-11
- **Intent**: Close the remaining Gate 2 test-evidence gap without modifying production behavior.
- **Changes**: The bounded process concurrency test now records each worker index and explicitly rejects any started worker whose exit status is nonzero or unavailable, even if it published a queue result. Existing timeout, exception, ledger-integrity, and lifecycle rollback assertions are preserved.
- **Validation**: PostgreSQL test collection completed with **6 passed, 7 skipped** locally; the seven database-backed tests remain skipped because Docker/PostgreSQL is unavailable. The full suite completed with **132 passed, 7 skipped** and the existing Starlette/httpx deprecation warning. Compileall and `git diff --check` passed.
- **Limitations**: Real PostgreSQL concurrency and transaction behavior remain unverified locally and require CI execution against PostgreSQL 16.

### Entry 33: Diagnose PostgreSQL Gate 2 CI failures
- **Date**: 2026-10-11
- **Intent**: Correct the PostgreSQL-specific constraint reflection and concurrent-test readiness setup without weakening integrity or allocator behavior.
- **Findings and changes**:
  - PostgreSQL reflects the correctly named `tip_hash` check with dialect-specific casts/parentheses. Validation and the integration assertion now use stable constraint identity plus semantic function/column/length checks; invalid-DML enforcement remains covered.
  - Spawned repository workers began with process-local readiness state `uninitialized`, causing `ensure_ready()` to return HTTP 503 before allocation. The test now runs explicit empty-ledger initialization in the parent and establishes the child readiness precondition before calling the repository directly.
- **Validation**: PostgreSQL test collection completed with **6 passed, 7 skipped** locally; Docker/PostgreSQL is unavailable. SQLite migration/integrity tests passed **32**; full suite passed **132** with **7 skipped** and the existing Starlette/httpx deprecation warning. Compileall and `git diff --check` passed.
- **Limitations**: Real PostgreSQL migration, constraint, and concurrency execution remains unverified locally and must be confirmed by CI against PostgreSQL 16.

### Entry 34: Correct PostgreSQL singleton-lock contention and reflection portability
- **Date**: 2026-10-11
- **Intent**: Remediate the reported PostgreSQL Gate 2 failure without reducing concurrency or weakening readiness/integrity checks.
- **Changes**:
  - PostgreSQL allocator access now locks an existing `ledger_state` singleton with `SELECT ... FOR UPDATE` before any initialization upsert, avoiding conflicting tuple-lock upgrades under concurrent writers. Conflict-safe insertion remains only for the genuinely absent-row initialization race.
  - The concurrent test explicitly initializes the empty ledger and establishes readiness in each spawned direct-service worker; production `ensure_ready()` remains unchanged.
  - Cross-dialect ledger check validation and reflected `tip_hash` assertions remain semantic/name-based while invalid-DML enforcement is retained.
- **Validation**: SQLite migration/integrity tests passed **32**; full suite passed **132** with **7 skipped** and the existing Starlette/httpx warning. Compileall and `git diff --check` passed. Real PostgreSQL execution remains pending CI.
- **Limitations**: The supplied CI excerpt showed cleanup SIGTERM (`-15`) rather than an underlying worker traceback; the lock-ordering fix is based on the current allocator path and must be confirmed by the real PostgreSQL job.

### Entry 35: Preserve PostgreSQL worker failures and bound successful cleanup
- **Date**: 2026-10-11
- **Intent**: Correct the concurrency-test harness after CI reported only synthetic `-15` cleanup exits.
- **Changes**:
  - Worker failures now include the child traceback, rather than only an exception representation.
  - Successful queue results are followed by bounded natural process joins; workers are no longer terminated merely because they are finishing cleanup after publishing a result.
  - On an actual worker/timeout failure, bounded termination and kill cleanup run without replacing the original failure with cleanup exit codes.
- **Validation**: PostgreSQL collection locally: **6 passed, 7 skipped**; full suite: **132 passed, 7 skipped**; compileall and `git diff --check` passed. No PostgreSQL server was available locally.
- **Limitations**: The real CI database run is still required to determine whether any underlying PostgreSQL allocator error remains after the harness correction.

### Entry 36: PostgreSQL Gate 2 CI verification
- **Date**: 2026-10-11
- **CI run**: [GitHub Actions run 38088656823](https://github.com/wshal/Audit-log-service/actions/runs/38088656823)
- **Reported result**: Passed. The PostgreSQL integration workflow completed successfully, including the database migration/constraint and independent-process concurrency coverage for Gate 2. This result was reported from the CI run by the repository operator; the run page was not independently fetchable from this environment.
- **Local comparison**: The local environment still has no PostgreSQL service; PostgreSQL collection remains **6 passed, 7 skipped**, while the default suite remains **132 passed, 7 skipped**.

### Entry 37: Bind verification to persisted ledger state
- **Date**: 2026-10-11
- **Intent**: Close a Gate 3 integrity gap where verification walked records and signatures but did not validate an existing allocator tip/sequence state.
- **Changes**:
  - `ChainVerificationService.verify_ledger()` now compares an existing `ledger_state` singleton with the verified record count and final record hash, returning a failed verification on mismatch.
  - A missing state row remains tolerated during explicit legacy startup initialization; `initialize_ledger_state()` still derives and persists the state only after record verification.
  - Added a regression test that tampers with `ledger_state.tip_hash` and asserts verification failure without changing the existing signature-specific failure ordering.
- **Validation**: Full default suite **133 passed, 7 skipped**, with the existing Starlette/httpx warning; compileall and `git diff --check` passed. PostgreSQL CI behavior was not rerun for this Gate 3 change.
- **Limitations**: Gate 3 still requires independent review of canonicalization, key rotation, nested redaction semantics, export proofs, and real PostgreSQL regression execution.

### Entry 38: Constrain initialization verification and document canonical JSON compatibility
- **Date**: 2026-10-11
- **Intent**: Remediate the Gate 3 verification-boundary and unsupported RFC 8785 claim findings without rewriting historical hashes.
- **Changes**:
  - Added a private initialization-only verification token/path used exclusively by `initialize_ledger_state()` to validate populated history before deriving a missing singleton. Ordinary verification now fails closed when populated records have no persisted state; empty-ledger behavior remains unchanged.
  - Reclassified `canonical_json()` as the project's historical Python `json.dumps`-based deterministic format, removed the RFC 8785 compatibility claim, and pinned representative numeric serialization outputs in compatibility tests. No serializer behavior or historical hashes changed.
  - Updated migration and authorization tests to initialize state explicitly before ordinary full-ledger verification where that was the intended setup.
- **Validation**: Focused verification/migration/integrity/canonicalization set **49 passed**; full suite **136 passed, 7 skipped**; compileall and `git diff --check` passed. PostgreSQL was not rerun locally.

### Entry 39: Record initialization verifier trust boundary
- **Date**: 2026-10-11
- **Design assumption**: The initialization-only verifier path is a trusted internal Python boundary used by `initialize_ledger_state()`. It is not an isolated capability that is inaccessible to every direct Python caller; ordinary HTTP/API callers cannot invoke it. This remains a known assumption unless a later security review identifies a concrete bypass.

### Entry 40: Gate 3 PostgreSQL CI verification
- **Date**: 2026-10-11
- **Workflow run**: [GitHub Actions run 38090070659](https://github.com/wshal/Audit-log-service/actions/runs/38090070659)
- **PostgreSQL job**: [postgres-integration job 114324520174](https://github.com/wshal/Audit-log-service/actions/runs/38090070659/job/114324520174)
- **Observed result**: Both the overall workflow and `postgres-integration` job passed. This is the first recorded real PostgreSQL execution for the Gate 3 checkpoint `a663d68`.
- **Local comparison**: Local validation remained **136 passed, 7 skipped** because PostgreSQL was unavailable locally; the CI run supplies the PostgreSQL integration evidence.

### Entry 41: Gate 4 documentation consistency checkpoint
- **Date**: 2026-10-11
- **Changes**: Reconciled README and audit-review validation claims with the current local baseline and recorded Gate 3 PostgreSQL CI evidence; clarified that the architecture formula uses the project's Python `json.dumps` compatibility format.
- **Validation**: `\.venv\Scripts\python -m pytest -q -W default` completed with **136 passed, 7 skipped**, and one existing Starlette/httpx deprecation warning. No SQLAlchemy resource warnings were observed. The seven skips remain PostgreSQL database-backed tests unavailable locally.
- **Limitations preserved**: Exact PostgreSQL CI test counts were not independently available; initialization-only verifier trust remains an internal Python-boundary assumption; no dedicated key-rotation workflow is claimed; and the serializer remains project-specific rather than RFC 8785-compliant.

### Entry 42: Timestamp ordering and strict JSON remediation
- **Date**: 2026-10-12
- **Intent**: Close the pre-release findings for mixed-precision timestamp ordering and non-standard JSON numeric constants while preserving historical hash-bound values.
- **Changes**:
  - Repository, tenant-scoped, compliance, and retention filters now compare parsed UTC instants in application code. Existing timestamp strings remain unchanged; malformed stored timestamps fail closed. This is correctness-first and may trade query performance for portability across SQLite and PostgreSQL.
  - Payload validation and canonical serialization recursively reject `NaN`, `Infinity`, and `-Infinity`; persisted JSON is parsed with strict constant rejection and invalid history returns `MALFORMED_RECORD` during verification.
  - Added regression tests for mixed-precision boundaries, nested non-finite request values, canonical serialization, and invalid persisted payloads. Updated release documentation to qualify truncation detection and distinguish current versus historical evidence.
- **Validation**: Focused integrity/canonicalization/scenario tests: **26 passed**. Full default suite after remediation: **142 passed, 7 skipped**, with the existing Starlette/httpx deprecation warning. The configured coverage command passed at **89.04% combined**. PostgreSQL remained unavailable locally; its seven database-backed tests were skipped. Compileall and `git diff --check` passed.
- **Limitations**: Timestamp filtering currently materializes the scoped candidate set before instant comparison; an indexed derived instant column would require an additive migration and integrity policy. The project remains intentionally non-RFC-8785 canonicalization, and valid signed tail truncation still requires an independent checkpoint.

### Entry 43: PR #5 PostgreSQL evidence and release wording
- **Date**: 2026-10-12
- **Merged revision**: `4b20228d847443728208daf53665f96852e04aa9`
- **CI evidence**: The supplied GitHub Actions evidence shows successful `postgres-integration` execution for source commit `23c0658` (the PR #5 head, whose tree was merged by `4b20228`): [workflow run 38173087249](https://github.com/wshal/Audit-log-service/actions/runs/38173087249), [postgres-integration job](https://github.com/wshal/Audit-log-service/actions/runs/38173087249/job/114569645659). The job completed successfully and included the PostgreSQL migration/concurrency test command from `.github/workflows/tests.yml`.
- **Evidence boundary**: Exact executed, passed, and skipped PostgreSQL test counts were not visible in the supplied job view and are not invented here. Local execution remains unavailable: the local PostgreSQL suite reports **6 passed, 7 skipped** because no PostgreSQL service is installed.
- **Documentation**: README wording now qualifies validly signed tail truncation as requiring an independently retained trusted checkpoint. The attestation submission date remains unchanged and requires owner confirmation if a final-release date is needed.

### Entry 44: Submission evidence reconciliation
- **Date**: 2026-10-12
- **Changes**: Updated README, audit review, requirements matrix, and engineering summary to distinguish the PR #5 CI source commit `23c0658` from merge commit `4b20228`. Preserved the exact supplied workflow/job links and the absence of detailed PostgreSQL counts. `ATTESTATION.md` was inspected but intentionally unchanged; its `2026-10-07` submission date remains owner-dependent.
- **Validation**: Documentation-only changes; application tree remains identical to merge commit `4b20228`. `git diff --check`, full tests, coverage, compilation, and local PostgreSQL collection were run; results are reported in the audit response.
## Entry 45 — Credential lifecycle hardening

**Date:** 2026-10-12
**Scope:** Prompt 3C credential lifecycle implementation.

Added an explicitly configured operator-managed credential manifest. Active,
expired, revoked, and superseded credentials are validated per request using
SHA-256 digests and constant-time comparison. Production requests fail with
HTTP 503 when the authority is missing, malformed, or unavailable; invalid
credentials return generic HTTP 401. Rotation and revocation use durable
atomic replacement helpers. The existing development API-key fallback remains
development-only compatibility behavior when no manifest path is configured.

Added lifecycle/security regression tests and documented the required separate
operator/service filesystem boundary. That boundary is a deployment
assumption and has not been established by this repository.

Validation:

- `.venv\Scripts\python -m pytest tests/test_security_controls.py -q` — 21 passed, 1 warning.
- `.venv\Scripts\python -m pytest tests/test_tenant_authorization.py tests/test_database_migrations.py tests/test_preflight_quarantine.py tests/test_integrity_regressions.py -q` — 112 passed, 1 warning.
- `.venv\Scripts\python -m pytest tests/postgres -q` — 6 passed, 7 skipped locally because PostgreSQL/Docker was unavailable, 1 warning.
- `.venv\Scripts\python -m pytest -q` — 150 passed, 7 skipped, 1 warning.
- `.venv\Scripts\python -m pytest -q --cov=app --cov-branch --cov-report=term --cov-fail-under=85` — 150 passed, 7 skipped; 87.93% combined coverage; threshold passed.
- `.venv\Scripts\python -m compileall -q app tests` — passed.
- `git diff --check` — passed with normal CRLF conversion warnings only.
## Entry 46 — Credential rotation durability and operator locking

**Date:** 2026-10-12
**Scope:** Prompt 3D remediation of credential lifecycle P1 findings.

Replaced one-call credential activation with staged delivery, explicit
acknowledgement, and activation. Added a persistent cross-process operator lock
(POSIX `fcntl.flock`, Windows one-byte `msvcrt.locking`) with bounded timeout
around provisioning, staging, acknowledgement, activation, and revocation.
Post-replacement directory-fsync failures are reported as ambiguous outcomes,
not falsely rolled back. Updated lifecycle documentation and tests for staged
credentials, lock timeout, independent-process provisioning, and ambiguous
activation.

Validation:

- `.venv\Scripts\python -m pytest tests/test_security_controls.py -q` — 26 passed, 1 warning.
- `.venv\Scripts\python -m pytest -q` — 155 passed, 7 skipped, 1 warning.
- `.venv\Scripts\python -m pytest -q --cov=app --cov-branch --cov-report=term --cov-fail-under=85` — 155 passed, 7 skipped; 86.94% combined coverage; threshold passed.
- `.venv\Scripts\python -m pytest tests/postgres -q` — 6 passed, 7 skipped locally because PostgreSQL/Docker was unavailable, 1 warning.
- `.venv\Scripts\python -m compileall -q app tests` — passed.
- `git diff --check` — passed with normal CRLF conversion warnings only.
## Entry 47 — Expiry-state manifest correction

**Date:** 2026-10-12
**Scope:** Prompt 3E targeted remediation.

Expiry is now derived from `expiresAt` during authentication and no longer
mutates an in-memory manifest record to the unsupported persisted status
`expired`. Added regression coverage proving expired credentials are rejected,
expired/revoked credentials remain valid manifest records after rewrites, and
staging another credential does not poison reloadability. Prompt 3D staged
activation and cross-process locking remain unchanged.

Validation:

- `.venv\Scripts\python -m pytest tests/test_security_controls.py -q` — 27 passed, 1 warning.
- `.venv\Scripts\python -m pytest -q` — 156 passed, 7 skipped, 1 warning.
- `.venv\Scripts\python -m compileall -q app tests` — passed.
- `git diff --check` — passed with normal CRLF conversion warnings only.

## Entry 48 — Bounded API abuse limiting

**Date:** 2026-10-12
**Scope:** Prompt 5 SEC-06 remediation.

Added a bounded process-local fixed-window limiter for `/audit` requests. It
limits unauthenticated traffic by client address and authenticated traffic by
credential identity and operation, returns generic HTTP 429 responses, and
uses bounded oldest-key eviction. A shared backend is still required before a
deployment can claim a global multi-worker or multi-instance quota.

Crash-safe idempotency was not invented: the append effect and a future
idempotency record require one atomic persistent transaction, so no idempotency
guarantee is claimed. This remains an explicit limitation.

Validation:

- `.venv\Scripts\python -m pytest tests/test_rate_limiting.py tests/test_security_controls.py -q` — 30 passed, 1 warning.
- `.venv\Scripts\python -m pytest -q` — 159 passed, 7 skipped, 1 warning.
- `.venv\Scripts\python -m pytest -q --cov=app --cov-branch --cov-report=term --cov-fail-under=85` — 159 passed, 7 skipped; 86.94% combined coverage; threshold passed.
- `.venv\Scripts\python -m pytest tests/postgres -q` — 6 passed, 7 skipped locally because PostgreSQL/Docker was unavailable, 1 warning.
- `.venv\Scripts\python -m compileall -q app tests` — passed.
- `git diff --check` — passed with normal CRLF conversion warnings only.

## Entry 49 — Crash-safe audit-event idempotency

**Date:** 2026-10-12
**Scope:** Prompt 6B implementation.

Added an Alembic-backed idempotency record keyed by authenticated credential,
tenant/legacy scope, method, endpoint, and client key. The request fingerprint,
audit record reference, and 24-hour expiry are committed in the same transaction
as the audit append and ledger-state update. Existing SQLite `BEGIN IMMEDIATE`
and PostgreSQL ledger-state locking remain the serialization points. Replays
return the original record; conflicting fingerprints return 409. An explicit
maintenance cleanup removes only expired idempotency rows.

Unknown commit outcomes are surfaced as HTTP 503 and are not blindly retried;
later authenticated requests look up the durable scoped result. Idempotency
metadata is not included in event payloads or historical hashes.

Validation:

- `.venv\Scripts\python -m pytest tests/test_idempotency.py tests/test_database_migrations.py -q` — 20 passed, 1 warning.
- `.venv\Scripts\python -m pytest -q` — 165 passed, 7 skipped, 1 warning.
- `.venv\Scripts\python -m pytest -q --cov=app --cov-branch --cov-report=term --cov-fail-under=85` — 165 passed, 7 skipped; 86.69% combined coverage; threshold passed.
- `.venv\Scripts\python -m pytest tests/postgres -q` — 6 passed, 7 skipped locally because PostgreSQL/Docker was unavailable, 1 warning.
- `.venv\Scripts\python -m compileall -q app tests` — passed.
- `git diff --check` — passed with normal CRLF conversion warnings only.

## Entry 50 — Idempotency concurrency evidence completion

**Date:** 2026-10-12
**Scope:** Additional independent-session duplicate-request regression.

Added a SQLite independent-session concurrency test proving that two identical
scoped keys produce one audit record, one idempotency record, and one replay.

Final revalidation after this test:

- `.venv\Scripts\python -m pytest -q` — 166 passed, 7 skipped, 1 warning.
- PostgreSQL collection remains 6 passed, 7 skipped locally because PostgreSQL/Docker was unavailable.

## Entry 51 — Final idempotency validation

**Date:** 2026-10-12

After the independent-session concurrency test was added, the final working
tree validation completed with **166 passed, 7 skipped**, 1 existing
Starlette/httpx deprecation warning, and **86.69% combined branch coverage**
against the configured 85% threshold. Compileall and `git diff --check` passed.
PostgreSQL collection remained **6 passed, 7 skipped** locally because no
PostgreSQL/Docker service was available; no local PostgreSQL execution is
claimed.

## Entry 52 — Tenant-scoped idempotency evidence

**Date:** 2026-10-12

Added coverage proving the same idempotency key is isolated across two V2
tenant/resource scopes. The focused idempotency suite now has 8 passing tests.
The final full-suite count after this addition is 167 passed, 7 skipped; the
seven PostgreSQL-backed cases remain skipped locally.

## Entry 53 — Final coverage after tenant-scope test

**Date:** 2026-10-12

Final configured coverage validation completed with **167 passed, 7 skipped**,
**86.77% combined branch coverage**, and the 85% threshold passed. The seven
skips remain PostgreSQL database-backed tests unavailable locally.

## Entry 54 - Idempotency acceptance remediation

**Date:** 2026-10-12

Implemented the bounded Prompt 6D remediation without changing ledger hash,
signature, authorization, recovery, or rate-limit semantics. The idempotency
migration now refuses routine destructive downgrade; expiration cleanup only
operates on an idle maintenance session and rolls back on failure. Added
regressions for cleanup transaction isolation, credential revocation before
replay, V1/V2 scope separation, and the HTTP ambiguous-commit 503 response,
plus PostgreSQL-only constraint, concurrency, and rollback tests.

Validation:

- `.venv\Scripts\python -m pytest tests/test_idempotency.py tests/test_database_migrations.py -q` - 28 passed, 1 warning.
- `.venv\Scripts\python -m pytest -q` - 172 passed, 10 skipped, 1 warning.
- `.venv\Scripts\python -m pytest -q --cov=app --cov-branch --cov-report=term --cov-fail-under=85` - 172 passed, 10 skipped; 86.73% combined coverage; threshold passed.
- `.venv\Scripts\python -m pytest tests/postgres -q` - 6 passed, 10 skipped locally because PostgreSQL/Docker was unavailable; no local PostgreSQL execution is claimed.
- `.venv\Scripts\python -m compileall -q app tests` - passed.
- `git diff --check` - passed with normal CRLF conversion warnings only.

## Entry 55 - PostgreSQL idempotency validation coverage

**Date:** 2026-10-12

Added PostgreSQL integration coverage for upgrading a database stamped at
`0001_schema_foundation` to the idempotency revision, preserving an existing
audit row and checking the idempotency unique constraint and foreign key. Added
a PostgreSQL deterministic committed-result/lost-response test that retries
through a fresh session and verifies one audit row, one idempotency row, the
same record identity, and ledger sequence advancement. The test is explicitly
fault injection after commit, not a claim of real network-failure simulation.

Validation:

- `.venv\Scripts\python -m pytest tests/postgres -q` - 6 passed, 12 skipped locally because PostgreSQL/Docker was unavailable.
- `.venv\Scripts\python -m pytest tests/test_idempotency.py tests/test_database_migrations.py -q` - 28 passed, 1 warning.
- `.venv\Scripts\python -m pytest -q` - 172 passed, 12 skipped, 1 warning.
- `.venv\Scripts\python -m pytest -q --cov=app --cov-branch --cov-report=term --cov-fail-under=85` - 172 passed, 12 skipped; 86.73% combined coverage; threshold passed.
- `.venv\Scripts\python -m compileall -q app tests` - passed.
- `git diff --check` - passed with normal CRLF conversion warnings only.

The PostgreSQL tests are configured for the existing PostgreSQL 16 CI service;
no local PostgreSQL execution is claimed.

## Entry 56 - Request boundary, endpoint inventory, and PostgreSQL CI execution guard

**Date:** 2026-10-12

Implemented the bounded Prompt 10B hardening batch. The application now rejects
HTTP request bodies over 256 KiB with HTTP 413, including streamed bodies that
do not provide a usable `Content-Length`. Added executable route-inventory and
security-contract tests covering authentication, rate limiting, role checks,
tenant/resource scope, and public health/readiness routes. The PostgreSQL CI job
now requires its database URL, emits a JUnit report, fails if any PostgreSQL
test is skipped, and uploads that report as an artifact. Local PostgreSQL skips
remain allowed when the service is unavailable.

Validation on the current working tree:

- `.venv\Scripts\python -m pytest tests/test_endpoint_inventory.py -q` - 6 passed, 1 warning.
- `.venv\Scripts\python -m pytest tests/test_security_controls.py -q` - 27 passed, 1 warning.
- `.venv\Scripts\python -m pytest tests/postgres -q -rs` - 6 passed, 12 skipped, 1 warning; PostgreSQL/Docker was unavailable locally, so no local PostgreSQL execution is claimed.
- `.venv\Scripts\python -m pytest -q --cov=app --cov-branch --cov-report=term-missing --cov-report=xml --cov-fail-under=85` - 178 passed, 12 skipped, 1 warning; 86.93% combined coverage and the 85% threshold passed.
- `.venv\Scripts\python -m compileall -q app tests` - passed.
- `git diff --check` - passed.

The endpoint streamed-body test invokes the ASGI middleware directly because
the local Starlette/httpx test transport rejects a chunked request before the
application receives it; the production guard itself is therefore tested at
the ASGI boundary. PostgreSQL execution remains a CI responsibility and must
run with `POSTGRES_TEST_REQUIRED=1` and zero skipped cases.

## Entry 57 - Prompt 10D streamed-body and endpoint-inventory remediation

**Date:** 2026-10-12

Corrected the Prompt 10B streamed-body path so overflow is converted to HTTP
413 through the complete application middleware stack, including CORS and the
quarantine/rate-limit middleware. The limiter now sends the bounded rejection
and presents downstream parsing with a disconnect, suppressing any secondary
400 response. Expanded endpoint inventory to include directly registered
`APIRoute` objects and added a synthetic direct-route regression. Added a
controlled protected-endpoint rate-limit test that asserts HTTP 429.

Validation:

- `.venv\Scripts\python -m pytest tests/test_endpoint_inventory.py -q` - 9 passed, 1 warning.
- `.venv\Scripts\python -m pytest tests/test_security_controls.py -q` - 27 passed, 1 warning.
- `.venv\Scripts\python -m pytest -q --cov=app --cov-branch --cov-report=term-missing --cov-report=xml --cov-fail-under=85` - 181 passed, 12 skipped, 1 warning; 86.89% combined coverage and the 85% threshold passed.
- `.venv\Scripts\python -m compileall -q app tests` - passed.
- `git diff --check` - passed.

The twelve local PostgreSQL skips remain database-backed tests unavailable
without PostgreSQL/Docker; no local PostgreSQL execution is claimed.

## Entry 58 - Response-start overflow completion

**Date:** 2026-10-12

Resolved the ASGI response-start edge case in the request-body guard. When
overflow is detected before any response starts, the middleware emits one
complete HTTP 413 response and suppresses downstream response messages. When a
downstream component has already started a response, the middleware does not
send a second response start or suppress the component's completion messages;
it presents `http.disconnect` to the downstream receiver and forwards the
downstream response sequence. Added deterministic ASGI event-sequence coverage
for this boundary.

Validation:

- `.venv\Scripts\python -m pytest tests/test_endpoint_inventory.py -q` - 10 passed, 1 warning.
- `.venv\Scripts\python -m pytest tests/test_security_controls.py -q` - 27 passed, 1 warning.
- `.venv\Scripts\python -m pytest tests/postgres -q -rs` - 6 passed, 12 skipped, 1 warning; PostgreSQL/Docker was unavailable locally.
- `.venv\Scripts\python -m pytest -q` - 182 passed, 12 skipped, 1 warning.
- `.venv\Scripts\python -m pytest -q --cov=app --cov-branch --cov-report=term-missing --cov-report=xml --cov-fail-under=85` - 182 passed, 12 skipped, 1 warning; 86.94% combined coverage and the 85% threshold passed.
- `.venv\Scripts\python -m compileall -q app tests` - passed.
- `git diff --check` - passed.

No local PostgreSQL execution is claimed; the existing CI-required guard
remains unchanged.

## Entry 59 - ASGI response-start invariant

**Date:** 2026-10-12

The request-body middleware now raises a deterministic `RuntimeError` when a
downstream component attempts a second `http.response.start` after the first
has been emitted. The duplicate event is never forwarded. Middleware-generated
413 responses continue to suppress downstream replacement responses, while a
valid downstream response after overflow-after-start continues to forward its
final body event.

Validation:

- `.venv\Scripts\python -m pytest tests/test_endpoint_inventory.py -q` - 11 passed, 1 warning.
- `.venv\Scripts\python -m pytest tests/test_security_controls.py -q` - 27 passed, 1 warning.
- `.venv\Scripts\python -m pytest tests/postgres -q -rs` - 6 passed, 12 skipped, 1 warning; PostgreSQL/Docker was unavailable locally.
- `.venv\Scripts\python -m pytest -q` - 183 passed, 12 skipped, 1 warning.
- `.venv\Scripts\python -m pytest -q --cov=app --cov-branch --cov-report=term-missing --cov-report=xml --cov-fail-under=85` - 183 passed, 12 skipped, 1 warning; 86.96% combined coverage and the 85% threshold passed.
- `.venv\Scripts\python -m compileall -q app tests` - passed.
- `git diff --check` - passed.

The local PostgreSQL skips remain non-evidence for PostgreSQL execution.

## Entry 61 - Local PostgreSQL setup attempt

**Date:** 2026-10-12

Inspected the Windows development environment before PostgreSQL integration
testing. Python 3.12.7 is available, but no `psql` client, Docker executable,
or PostgreSQL Windows service was found. The venv did not contain the declared
PostgreSQL driver, so the existing `requirements-postgres.txt` profile was
installed without changing tracked files; `psycopg` 3.3.6 is now available in
the venv. No PostgreSQL server or database was installed or modified because
that would require a separate service/installer decision and administrative
environment changes.

The PostgreSQL suite therefore remains **6 passed, 12 skipped** locally, with
no database-backed execution claimed. A dedicated PostgreSQL 16 service and
isolated `audit_test` database using the CI URL scheme remain the next required
environment prerequisite.

## Entry 60 - ASGI protocol-error deployment limitation

**Date:** 2026-10-12

Documented the request-body middleware's deployment boundary in
`docs/architecture.md`. The supported local entry point is Uvicorn
(`uvicorn app.main:app --port 8000`). Before response start, overflow produces
one complete 413 response. After response start, the status cannot be replaced;
the middleware sends `http.disconnect` downstream and forwards valid completion
events. Duplicate `http.response.start` raises the deterministic ASGI protocol
error and is not forwarded. A real Uvicorn/client transport test for the
client-visible result after that uncaught protocol error was not feasible
without adding a test-only route or changing deployment configuration, so no
server-level termination guarantee is claimed.

## Entry 62 - Startup signing validation and final working-tree evidence reconciliation

**Date:** 2026-10-12

**Root cause:** An empty production ledger could complete database preflight and
report readiness before the lazily loaded Ed25519 signing key was first needed.
The first signing-dependent write could then fail after a false-positive ready
response.

**Remediation:** Startup now validates the configured private key and public-key
ring before integrity preflight may transition the service to healthy. Missing or
malformed production private-key material, malformed public-key-ring entries,
and active private/public-key mismatch follow the existing quarantine path.
The development fallback remains non-production only. Health and readiness
responses do not disclose key material. The implementation is in
`app/crypto/signer.py` and `app/main.py`; lifecycle coverage is in
`tests/test_preflight_quarantine.py`.

**Accepted validation evidence on the current uncommitted working tree:**

- Focused signing/quarantine/security/endpoint suite: **77 passed, 1 warning**.
- Dedicated required-mode local PostgreSQL 16 suite against guarded `audit_test`:
  **18 passed, zero skipped, 1 warning**. It used `PGPASSFILE`,
  `POSTGRES_TEST_DATABASE_URL`, and `POSTGRES_TEST_REQUIRED=1`; no credential
  contents were recorded.
- Default full suite with configured coverage: **189 passed, 12 skipped, 1
  warning**, **87.63% combined coverage**, with the 85% gate passed. The twelve
  PostgreSQL-backed skips occur because that separate default invocation has no
  PostgreSQL connection configuration; they are not added to the dedicated
  PostgreSQL result.
- `python -m compileall -q app tests` and `git diff --check` passed.

The warning is the existing Starlette/TestClient deprecation warning. These
changes remain uncommitted, so the committed base SHA does not attest to the
complete validated working tree. Tail-truncation detection without an
independent trusted checkpoint, process-local rate limiting without a shared
backend, key custody/rotation/runtime reload, backup/restore drills, deployment
TLS controls, and scale validation remain separate limitations.

## Entry 63 - Phase B checkpoint contract and integrity verification

**Date:** 2026-10-12

Implemented the bounded Phase B checkpoint contract in the current uncommitted
working tree. `app/checkpoint.py` defines strict version-1 checkpoint fields,
deterministic project-specific Python JSON signing bytes, separate Ed25519
checkpoint signing, trusted-key verification, and explicit verification status
values. `app/services/checkpoint_verifier.py` reuses the authoritative full-ledger
verifier before returning `MATCHING_PREFIX` or `UNANCHORED_SUFFIX`. The test-only
`tests/checkpoint_store.py` remains an in-memory test double; no production
publisher, external store, migration, or CI change was introduced.

Independent review and remediation added adversarial coverage for earlier
signature/chain tampering, missing ledger state, invalid V1/V2 transition
evidence, corrupted suffixes, malformed checkpoints, identity mismatch, and
missing integrity authorization context.

Current working-tree validation:

- Focused security/integrity/authorization/migration/idempotency/checkpoint suite:
  **191 passed, 1 warning**.
- Full configured coverage suite: **208 passed, 12 skipped, 1 warning**;
  **87.95% combined coverage**, with the configured 85% threshold passed.
- Required local PostgreSQL suite: **18 passed, zero skipped, 1 warning**.
- Compileall and `git diff --check`: passed.

These results describe the uncommitted working tree, not a committed revision
or CI run. External checkpoint storage, immutable retention, monotonic
publication, independent key custody, outage policy, and detection of valid
tail truncation beyond a trusted checkpoint remain unresolved owner decisions.

## Entry 64 - P0 attestation, endpoint inventory, and threat-model evidence

**Date:** 2026-10-13

Reviewed the post-PR #7 repository state without changing application behavior.
The local branch is `security/checkpoint-release-prep` at source commit
`76e93211137e02d222d320757dab8a5e1f635bbc`; `origin/main` is the merged PR #7
revision `d21195c7550bc747e6130b1630d7e721ffe80540`. The PR #7 pull-request
workflow and `postgres-integration` job were retrieved as successful for the
source commit. Detailed GitHub job test counts were not available through the
accessible log endpoint and are not claimed here.

Added an evidence-oriented attestation update, `docs/endpoint_security_inventory.md`,
and `docs/threat_model.md`. The inventory maps every registered health and audit
route to authentication, role/capability, tenant/resource scope, input limits,
state-changing behavior, and named evidence. The threat model records implemented
controls separately from deployment assumptions and residual risks, including the
process-local rate limiter, external checkpoint requirement, key custody, TLS,
backup, and dependency-scanning limitations.

The attestation retains the candidate declaration and existing owner-provided
identity/date values, binds the PR source and merged revisions, links claims to
source/tests, and explicitly leaves final owner confirmation and signing
outstanding. No application code, tests, schema, migration, or Git history was
changed by this evidence pass.

## Entry 65 - Final attestation and release-gap register

**Date:** 2026-10-13

Finalized the evidence-oriented attestation after confirming the merged PR #7
revision (`d21195c7550bc747e6130b1630d7e721ffe80540`) and source revision
(`76e93211137e02d222d320757dab8a5e1f635bbc`). The original owner-confirmed
identity, assignment, development date, submission date, and declaration were
retained. A typed attestation date of 2026-10-13 was recorded separately.

Generated two identical deterministic `git archive --format=tar HEAD`
artifacts for the merged HEAD tree and recorded SHA-256
`46a2ba4244a1a3adbbb5d863558ecc335384fd7fdd91058de68f3691040651a4` in
`ATTESTATION.md`. The digest excludes the current uncommitted documentation
updates and therefore does not purport to identify a future commit.

Expanded the claim-to-evidence matrix and added
`docs/release_gap_register.md`, separating mandatory owner gates, P0 technical
gaps, evidence gaps, deployment-dependent controls, and deferred scope. The
register keeps the process-local limiter, key custody, TLS/proxy, dependency
scanning, backup/recovery, observability, and external-checkpoint limitations
explicit. Prompt 23 has not started.

Validation in this task was documentation/source consistency only:
`git diff --check` passed (with the existing line-ending warning for
`ATTESTATION.md`) and `tests/test_endpoint_inventory.py` completed 11 passed
with one existing Starlette/httpx deprecation warning. Previously recorded
full-suite and PostgreSQL results remain attributed to their exact source
revision and are not re-counted as this documentation run.

## Entry 66 - Attestation provenance correction

**Date:** 2026-10-13

Verified the PR #7 provenance from Git history: source branch
`security/checkpoint-release-prep` at `76e93211137e02d222d320757dab8a5e1f635bbc`
was merged into `main` as `d21195c7550bc747e6130b1630d7e721ffe80540` on
2026-10-13 at 00:28:07 +0530. The attestation now treats merged `main` as
the primary code baseline, removes obsolete owner-confirmation placeholders
for the confirmed identity and dates, and distinguishes the uncommitted
documentation from the committed archive digest. No other branch contains
additional committed work represented as part of the attested `main` baseline.

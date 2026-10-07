# AI Usage and Decision Log

This document records the traceability of AI assistance throughout the development of the **Tamper-Evident Audit Log Service** in accordance with Schwab requirements (Section 0.3, 4.3, and 7).

## Principles & Quality Gates
- **Human-in-the-Loop**: All architectural boundaries, cryptographic choices, redaction designs, and test suites are directed, reviewed, and signed off by the engineer.
- **Traceability**: Decisions to accept, modify, or reject AI proposals are documented here.
- **Verification**: All code passes automated unit and integration tests, static typing checks, and manual tamper-detection validation.

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





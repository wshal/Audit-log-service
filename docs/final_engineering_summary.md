# Final Engineering Summary

**Project**: Tamper-Evident Audit Log Service  
**Organization**: Charles Schwab & Co., Inc. — Interview Assessment  
**Candidate**: Vishal Gaikwad (`gaikwadvishal2001@gmail.com`)  
**Submission Date**: 2026-10-07  

---

## 1. Executive Summary & Goals Met

This submission implements a working **Tamper-Evident Audit Log Service prototype** covering Scenarios A, B, and C. Production hardening boundaries are explicitly documented in `docs/audit_review.md`.
- **Scenario A**: High-throughput append-only event ingestion, multi-parameter querying with pagination, sequential SHA-256 cryptographic chaining, and an automated verification engine that pinpoints broken links and content tampering.
- **Scenario B**: Policy-driven retention soft-archival without breaking cryptographic chains, structured field redaction with an immutable redaction manifest, and integrity-hashed bulk export bundles. Signed independent inclusion proof remains future work.
- **Scenario C**: Ambiguity resolution and normalization of regulatory requirements into an actionable compliance engine that audits client data access trails, calculates actor-level summaries, flags policy anomalies, and certifies ledger authenticity.

---

## 2. Key Architectural Decisions & Rationale

| Decision | Selected Approach | Trade-offs & Alternatives Considered |
|---|---|---|
| **Cryptographic Hashing** | SHA-256 over deterministic Python JSON | SHA-256 is globally recognized and hardware-accelerated. This serializer is deterministic within the supported Python data model but is not a complete RFC 8785 implementation. |
| **Tamper Detection Granularity** | Sequence-based verification identifying exact broken record ID & violation category | Full Merkle Trees offer $O(\log n)$ membership proofs, but linear hash chaining is $O(n)$ for verification, simple to explain, perfectly suited for sequential audit trails, and requires zero tree-rebalancing overhead on append. |
| **Structured Redaction** | Salted cryptographic commitment per redacted field | Considered deleting old blocks or re-hashing forward (which would rewrite history and destroy audit immutability). Our commitment scheme allows masking plaintext PII while mathematically preserving the original block content hash. |
| **Storage Engine** | Relational Ledger (SQLite / PostgreSQL schema with composite indexes) | NoSQL/Document stores lack strict relational constraints. Relational storage ensures strict unique monotonic sequence constraints and easy tamper-demonstration. |

---

## 3. Assumptions & Limitations

1. **Monotonic Sequence Concurrency**: In high-concurrency production deployments (e.g. 50,000 writes/sec), a distributed sequencer (e.g., Kafka partition sequence or Redis atomic counter) should assign sequence numbers before persisting to relational storage.
2. **Key Management**: Redaction salts and verification keys are stored in the database metadata; in an enterprise environment, these can be augmented with AWS KMS / HashiCorp Vault envelope encryption.
3. **Storage Tiering**: Archival currently flags records as `is_archived`; in production, archived cold blocks can be backed up to AWS S3 Glacier with object lock (WORM) storage.

---

## 4. Verification and Quality Sign-Off

- **Historical test record**: The earlier implementation checkpoint reported 55 tests; that count is retained as historical context.
- **Historical test result**: The earlier 93-test checkpoint is retained as historical context.
- **Current working-tree validation**: The earlier PostgreSQL-unconfigured run was **249 passed, 12 skipped**. With the guarded PostgreSQL environment configured, the current default suite completed locally with **261 passed, 0 skipped** and one existing Starlette/httpx dependency deprecation warning. The focused endpoint/integrity/security run completed with **99 passed, 1 warning**. Compilation and `git diff --check` passed. The current PostgreSQL 16.15 suite completed **22 passed, zero skipped, 1 warning** against `audit_test`. These results apply to the current uncommitted tree; coverage was not rerun and previously recorded coverage results remain historical.
- **PostgreSQL evidence**: PR #7's [workflow](https://github.com/wshal/Audit-log-service/actions/runs/38293842786) and [postgres-integration job](https://github.com/wshal/Audit-log-service/actions/runs/38293842786/job/114960061221) passed for source `76e9321`, merged as `d21195c`. Exact PostgreSQL executed/passed/skipped counts were not independently available from the accessible job logs, so no CI count is claimed.
- **Backend limitation**: The local default suite exercises isolated SQLite; the separate local PostgreSQL run and recorded CI job provide PostgreSQL evidence. Neither alone establishes vulnerability-free behavior, independent multi-host coverage, or CI validation tied to a final committed revision.
- **Git History**: PR #7 source `76e9321` was merged to `main` as `d21195c`; local validation and CI evidence are reported separately.
- **Attestation**: `ATTESTATION.md` records the confirmed candidate metadata, typed sign-off, and claim-to-evidence matrix. Its reproducible SHA-256 archive digest identifies the merged `main` revision `d21195c7550bc747e6130b1630d7e721ffe80540`; it is not a cryptographic signature or independent third-party verification. Any final submission archive must be generated from the final committed revision and recorded without creating a circular digest update.

## 5. Phase 1B Authorization and Integrity Remediation

The `security/tenant-authorization-p0` branch adds explicit tenant/resource grants,
legacy access capability checks, repository/service authorization scopes, PII
projection, positive scoped lifecycle behavior, V2 attribution-bound hashing,
signed V1/V2 transition evidence, atomic first-V2 persistence, and additive
legacy migration tests. Historical V1 records are not rewritten or assigned
tenants. The V1/V2 physical table and global sequence remain a documented
trade-off; independently retained checkpoints are still required to detect
valid signed tail truncation.

## 6. Phase B checkpoint contract

`app/checkpoint.py` defines a strict version-1 checkpoint payload and separate
Ed25519 checkpoint-signing interface. `app/services/checkpoint_verifier.py`
validates checkpoint identity and signature, invokes the authoritative full
ledger verifier, and then returns explicit `MATCHING_PREFIX`,
`UNANCHORED_SUFFIX`, or fail-closed statuses. The implementation is covered by
`tests/test_checkpoints.py` and has no production publication or external store.
It therefore cannot establish immutable external history, latest-checkpoint
status, export completeness, or detection of valid tail truncation beyond the
trusted checkpoint. Those require an owner-approved external authority,
retention, and key-custody design.

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
- **Current uncommitted working-tree validation**: The default coverage command completed locally with **208 passed, 12 skipped**, one dependency deprecation warning, and **87.95% combined coverage**; the 85% gate passed. The twelve skips are PostgreSQL-backed tests not selected without PostgreSQL connection configuration. A separate required-mode PostgreSQL 16 run against `audit_test` completed **18 passed, zero skipped**. These are distinct executions and are not summed. The earlier 91.08% line / 78.76% branch / 88.27% combined result is historical.
- **PostgreSQL evidence**: PostgreSQL integration infrastructure and tests are under `tests/postgres`. Gate 3 passed, and PR #5's [workflow](https://github.com/wshal/Audit-log-service/actions/runs/38173087249) and [postgres-integration job](https://github.com/wshal/Audit-log-service/actions/runs/38173087249/job/114569645659) passed for source `23c0658`, whose application tree was merged as `4b20228`. Exact PostgreSQL executed/passed/skipped counts were not independently available, so no detailed CI count is claimed.
- **Backend limitation**: The local default suite exercises isolated SQLite; the separate local PostgreSQL run and recorded CI job provide PostgreSQL evidence. Neither alone establishes vulnerability-free behavior, independent multi-host coverage, or CI validation tied to a final committed revision.
- **Git History**: Review and commit state are maintained by the repository owner; this working tree contains the reviewed implementation diff.
- **Attestation**: `ATTESTATION.md` contains the candidate declaration and submission date, but it does not bind this uncommitted working tree to a final commit or archive digest. Final revision binding and owner confirmation remain outstanding.

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

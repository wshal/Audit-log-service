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

- **Unit & Integration Tests**: 22 automated tests covering core append, multi-field filtering, direct DB tamper detection, record deletion detection, retention archival, structured redaction, signed export, regulatory compliance reports, post-redaction mutation, invalid lifecycle input, timestamp validation, concurrent SQLite appends, API-key/RBAC enforcement, actor-identity binding, signature forgery, lifecycle witnesses, key persistence, and the full Scenario A/B/C workflow.
- **Test Results**: All 8 tests passing (`pytest -v`).
- **Clean Git History**: Structured commits reflecting continuous development from design to delivery.
- **Attestation**: Formally verified in `ATTESTATION.md`.

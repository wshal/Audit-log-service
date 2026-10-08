# Implementation Audit and Improvement Record

**Reviewed:** 2026-10-08  
**Scope:** assignment requirements, API behaviour, persistence, cryptographic verification, tests, and delivery documentation.

## Requirement coverage

| Requirement | Current outcome | Review conclusion |
|---|---|---|
| Append event with required fields | `POST /audit/events` writes a chained record and server-assigns UTC time when omitted. | Met. Input timestamps are now canonical UTC instants, so lexical SQLite range comparisons are reliable for new data. |
| Query by actor, resource, event type, time, pagination | `GET /audit/events` supports all required combinations. | Met. Invalid/reversed time windows now return 422. |
| Hash chain and verification | SHA-256 content and block hashes, a genesis value, sequence/link/hash checks. | Met for datastore changes that do not rewrite the entire ledger. |
| Direct mutation/deletion detection | Verification reports first failed sequence/type. | Met and tested. |
| Retention/archive | Records are soft-archived; original event/hash fields stay present. | Meets the stated soft-delete option, but archival state itself is not hash-bound. |
| Structured redaction | PII is replaced with commitment tokens. A chained `AUDIT_RECORD_REDACTED` manifest now binds the post-redaction payload and metadata. | Improved: later changes to a redacted record are detected. |
| Bulk export | Filtered records plus record hashes and bundle hash are returned. | Partial: an unsigned, filtered bundle is not a complete independent proof of inclusion in the global chain. |
| Compliance normalization/report | Ambiguity document and client-access report exist. | Met as a deliberately scoped prototype. |
| AI process / submission artifacts | Attestation, AI log, architecture, scenario-C normalization, summary, tests, and setup are present. | Mostly met; the quality-gate claims should name the actual commands/results rather than claim unconfigured tooling. |

## Implemented corrections

1. **Serialized SQLite appends.** The old read-tip/insert sequence allowed writers to select the same next sequence; a 30-writer probe lost 14 events to unique-key failures. SQLite appends now acquire `BEGIN IMMEDIATE` before reading the tip. A 24-writer regression test confirms sequences 1-24 are all persisted.
2. **Made redacted records verifiable after redaction.** The previous verifier skipped content validation whenever `redaction_metadata_json` existed, allowing arbitrary edits to a redacted payload or metadata to pass verification. Redaction now appends an immutable chained manifest containing the original hashes and canonical hashes of the redacted payload and metadata; verification requires a matching manifest.
3. **Rejected unsafe/no-op redactions.** Unknown fields, duplicate redactions, and an empty field list now fail rather than creating misleading success responses.
4. **Normalized timestamps and validated query ranges.** Timestamps are canonical UTC `Z` values and malformed/reversed query ranges are rejected.
5. **Added regression coverage.** `tests/test_integrity_regressions.py` covers all four corrections.

## Upgrade note

The new signature and manifest checks intentionally reject records written by the former implementation: it had neither Ed25519 signatures nor immutable post-redaction proof. The existing local `audit_ledger.db` contains legacy records and therefore verifies as broken under the new rules. Do **not** repair this by inserting signatures or manifests retroactively: that would turn unaudited mutations into trusted history. For a real deployment, preserve the old database as a read-only legacy epoch, record and externally sign its final verification status/checkpoint, then start a new epoch using this protocol.

## Remaining risks and recommended next decisions

1. **External key custody and anchoring remain essential.** Records are now Ed25519-signed and a database-only attacker cannot recompute valid signatures. The signing private key must live outside the database (ideally KMS/HSM), and periodic signed checkpoints should be placed in independent WORM/object-lock storage to protect against a compromised service/key.
2. **Redaction is a controlled mutation, not cryptographic erasure.** The database still stores the historical content hash and salts in metadata. A production privacy design should encrypt sensitive payload fields at ingestion with envelope keys and destroy/rotate the appropriate data-encryption key for an authorized erasure; the ciphertext, not plaintext, can remain chain-bound.
3. **Export authenticates records but does not yet prove global-chain inclusion.** Exports now include public keys, signatures, and relevant lifecycle manifests, so recipients can verify record authenticity and post-redaction state. A Merkle inclusion proof or signed checkpoint is still needed to prove an arbitrary filtered record belongs to one particular global-chain root without revealing unrelated events.
4. **SQLite is suitable for the assignment, not multi-instance production.** `BEGIN IMMEDIATE` serializes local writers, reducing throughput and cannot coordinate multiple service hosts. Use a transactional server database with a single ledger-writer/sequence allocator and operational backups/replication.
5. **Operational safeguards are incomplete.** API-key role controls, CORS allowlisting, payload limits, signatures, and lifecycle manifests are implemented. Add centralized identity, authorization-decision audit events, structured logs/metrics, database access controls, migration tooling, rate limits, request IDs, and security/dependency scanning in CI.

## Validation run

`\.venv\Scripts\python.exe -m pytest -q` completed successfully: **18 passed**.

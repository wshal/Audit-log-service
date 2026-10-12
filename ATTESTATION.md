# ATTESTATION

## Submission identity and scope

- **Candidate name**: Vishal Gaikwad
- **Email**: `gaikwadvishal2001@gmail.com`
- **Assignment**: Build an AI-Assisted Software Engineering System - Audit Log Service (Version 2.0)
- **Repository**: https://github.com/wshal/Audit-log-service
- **Source branch for PR #7**: `security/checkpoint-release-prep`
- **PR #7 source revision**: `76e93211137e02d222d320757dab8a5e1f635bbc`
- **Merged `main` revision**: `d21195c7550bc747e6130b1630d7e721ffe80540`
- **Committed code scope**: authorization, integrity and recovery hardening; PostgreSQL migration, allocator, concurrency, rollback, checkpoint, credential, idempotency, rate-limit, and request-boundary work present in merged `main`.
- **Current evidence scope**: the endpoint inventory, threat model, release-gap register, Prompt 24 rate-limit contract documentation, and prior attestation are committed in `3e5d242`; this digest metadata is the intended second, metadata-only commit and is not part of the `3e5d242` archive.

## Dates and sign-off

- **Original development start date**: `2026-10-07`
- **Original submission date**: `2026-10-07`
- **Final revision / merge date**: `2026-10-13` (Git commit date for PR #7 merge, `d21195c7550bc747e6130b1630d7e721ffe80540`, at `00:28:07 +0530`)
- **Attestation/sign-off date**: `2026-10-13` (typed sign-off date for this attestation update)

## Artifact identity

The code revision being attested is merged `main` revision
`d21195c7550bc747e6130b1630d7e721ffe80540`. The documentation baseline is
commit `3e5d2428fc448d7a5296fb6b299a6202c99b3aee`. A deterministic Git archive
of that first documentation commit was generated with
`git archive --format=tar 3e5d2428fc448d7a5296fb6b299a6202c99b3aee` and hashed
with SHA-256. Repeating the command produced the same digest:

- **Artifact**: Git archive TAR of `3e5d2428fc448d7a5296fb6b299a6202c99b3aee`
- **SHA-256**: `a764ab11935917b6f55a7d28360735f4a6ef69580f78309bea65d1d0c3e95c14`
- **Archive size**: 686,080 bytes
- **Reproducibility check**: two independently generated archives matched byte-for-byte.

This digest identifies the first documentation commit's archive only. The
second commit contains this digest metadata and is deliberately not represented
as covered by the digest, avoiding a circular archive update.

## Candidate declaration

> I, Vishal Gaikwad, attest that this submission is my own individual work, completed on my own machine and accounts, and that it honestly reflects my development process and use of AI.

AI assistance was used during development and review. The chronological record is maintained in `AI_LOG.md`. The candidate confirms that this disclosure accurately reflects the development process and accepts responsibility for reviewing and defending the resulting work.

**Typed candidate sign-off — 2026-10-13:** Vishal Gaikwad

This is a typed attestation, not a cryptographic signature or independent
third-party verification.

## Claim-to-evidence matrix

| Claim | Source evidence | Validation evidence | Status |
|---|---|---|---|
| Tenant/resource authorization and actor attribution | `app/authorization.py`, `app/security.py`, `app/routers/`, `app/storage/repository.py` | `tests/test_tenant_authorization.py`, `tests/test_security_controls.py` | Implemented and tested in the recorded suites |
| Hash/signature integrity, V1/V2 compatibility, migration safety | `app/crypto/`, `app/services/verifier.py`, `app/storage/database.py`, `alembic/` | Integrity, migration, and PostgreSQL tests; PR #7 checks successful | Implemented; exact CI test counts not independently available here |
| PostgreSQL concurrency and rollback | `app/storage/repository.py`, `tests/postgres/test_concurrency.py` | PR #7 `postgres-integration` job succeeded; local required-mode runs recorded in `AI_LOG.md` | Evidence available; detailed PR #7 counts unavailable from accessible logs |
| Credential, request, rate-limit, idempotency, and quarantine controls | `app/credential_store.py`, `app/main.py`, `app/rate_limit.py`, `app/storage/repository.py`, `app/runtime_state.py` | Named tests in `docs/requirements_test_matrix.md` and CI workflow | Implemented in prototype scope; deployment assumptions remain |
| Local signed checkpoint comparison | `app/checkpoint.py`, `app/services/checkpoint_verifier.py` | `tests/test_checkpoints.py` | Local verification only; no external immutable trust anchor |
| Endpoint inventory and threat model | `docs/endpoint_security_inventory.md`, `docs/threat_model.md`, `tests/test_endpoint_inventory.py` | Route inventory and boundary tests | Documentation and executable inventory present |

## Known limitations and evidence boundaries

- The service uses configured API-key principals; no external identity provider is included.
- The in-process rate limiter is not a distributed/global limiter.
- Checkpoints are locally verified signed objects; external publication, immutable storage, key custody, and independent detection of every valid-prefix tail truncation are not implemented.
- The project-specific Python JSON serialization format is not RFC 8785/JCS.
- PostgreSQL CI success is recorded for PR #7 source revision `76e9321`; detailed executed/passed/skipped counts were not independently retrievable during this update.
- The attestation is not itself a cryptographic signature, archive digest, or proof of independent third-party review.

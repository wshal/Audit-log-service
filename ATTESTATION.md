# ATTESTATION

## Submission identity and scope

- **Candidate name**: Vishal Gaikwad
- **Email**: `gaikwadvishal2001@gmail.com`
- **Assignment**: Build an AI-Assisted Software Engineering System - Audit Log Service (Version 2.0)
- **Repository**: https://github.com/wshal/Audit-log-service
- **Source branch for PR #7**: `security/checkpoint-release-prep`
- **PR #7 source revision**: `76e93211137e02d222d320757dab8a5e1f635bbc`
- **Merged `main` revision**: `d21195c7550bc747e6130b1630d7e721ffe80540`
- **Historical PR #7 merged code scope**: authorization, integrity and recovery hardening and the PostgreSQL, checkpoint, idempotency, rate-limit, and request-boundary work present in merged `main` revision `d21195c`.
- **Substantive release branch**: `review/release-docs-final`
- **Substantive release revision**: `feef52876d310f9001ebfddfbc90b1f24db7fbbd`
- **Substantive release scope**: the credential-manifest, signing-key, query-resource, test-cleanup, and documentation changes included in the substantive release commit and now present in merged `main`.
- **Current CI evidence**: PR #8 workflow run `38342250230` passed for `feef528`; detailed CI test counts were not independently available from the accessible logs.

- **Final merged `main` revision**: `ccc2db2e2c397f8637df0bc61fcb270b3a511a46` (merge commit for PR #10, `security/p0-rate-limit-app-integration`)
- **PR #10 source revision**: `f062894a0bb12776a583371f84a0ca104e1cd1bb`
- **Final CI workflow**: [run 38347892406](https://github.com/wshal/Audit-log-service/actions/runs/38347892406), triggered by the merge to `main` and testing `ccc2db2e2c397f8637df0bc61fcb270b3a511a46`; `test`, `postgres-integration`, and `rate-limit-integration` all completed successfully.
- **Final CI jobs**: [test](https://github.com/wshal/Audit-log-service/actions/runs/38347892406/job/115133419853), [postgres-integration](https://github.com/wshal/Audit-log-service/actions/runs/38347892406/job/115133419904), and [rate-limit-integration](https://github.com/wshal/Audit-log-service/actions/runs/38347892406/job/115133419762).
- **Final CI artifacts**: `coverage-report` (`sha256:9e1e31709f502616c78e109b1c14e41c685fa5192b77ef8ab445c900106bc6ba`), `postgres-test-results` (`sha256:9723f22b690bc0d7b131dc78cab638b2d39dcbe1f9cf6e42504f09354ab0e41c`), and `rate-limit-test-results` (`sha256:ef753f2d329801afb252c5e732005675e65aadfa3321e1969394758401fc79e5`). The recorded job outputs report 253 passed, 18 skipped, 1 warning for the general suite with 87.18% combined coverage; 22 passed, 0 skipped, 1 warning for PostgreSQL; and 8 passed, 0 skipped, 1 warning for Redis.

## Dates and sign-off

- **Original development start date**: `2026-10-07`
- **Original submission date**: `2026-10-07`
- **PR #7 merge date**: `2026-10-13` (Git commit date for merge revision `d21195c7550bc747e6130b1630d7e721ffe80540`, at `00:28:07 +0530`)
- **Final merged `main` commit date**: `2026-10-13T10:14:15+05:30` (`ccc2db2e2c397f8637df0bc61fcb270b3a511a46`)
- **Attestation/sign-off date**: `2026-10-13` (typed sign-off date for this attestation update)

## Artifact identity

The historical documentation baseline is commit
`3e5d2428fc448d7a5296fb6b299a6202c99b3aee`. Its deterministic Git archive was
generated with `git archive --format=tar
3e5d2428fc448d7a5296fb6b299a6202c99b3aee` and hashed with SHA-256:

- **Historical artifact**: Git archive TAR of `3e5d2428fc448d7a5296fb6b299a6202c99b3aee`
- **Historical SHA-256**: `a764ab11935917b6f55a7d28360735f4a6ef69580f78309bea65d1d0c3e95c14`
- **Historical archive size**: 686,080 bytes
- **Historical reproducibility check**: two independently generated archives matched byte-for-byte.

That historical digest covers the first documentation commit only. It does not
cover the substantive release revision or any later metadata-only commit.

The substantive release revision described by this attestation is
`feef52876d310f9001ebfddfbc90b1f24db7fbbd`. A Git TAR archive generated
directly from that revision is:

- **Artifact**: `audit-log-service-v2.0-feef528-20261013.tar`
- **SHA-256**: `c026a21581a2a58040f09080e3c1db6207649cc69039c38bf1a79a08751f3aaf`
- **Archive size**: 727,040 bytes

The archive covers exactly the substantive release commit above. If this
attestation is updated in a later metadata-only commit, that later commit is
not included in this archive and the digest does not cover it. A new archive
and digest would be required for any later substantive revision.

The final merged code revision has also been archived separately:

- **Artifact**: `audit-log-service-v2.0-ccc2db2-20261013.tar`
- **Source revision**: `ccc2db2e2c397f8637df0bc61fcb270b3a511a46`
- **SHA-256**: `96d190d4d7378524e3cff998a083ed2746dec5996d7ae1d73b159219b78b682c`
- **Archive size**: 747,520 bytes
- **Generation**: `git archive --format=tar --output=audit-log-service-v2.0-ccc2db2-20261013.tar ccc2db2e2c397f8637df0bc61fcb270b3a511a46`

This final archive covers the committed `ccc2db2` tree only. It does not include
this later attestation edit or any subsequent metadata-only attestation commit.

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
| Credential, request, rate-limit, idempotency, and quarantine controls | `app/credential_store.py`, `app/main.py`, `app/rate_limit.py`, `app/storage/repository.py`, `app/runtime_state.py` | Named tests in `docs/requirements_test_matrix.md`; final CI run 38347892406 completed the general, PostgreSQL, and Redis jobs | Implemented in prototype scope and present in merged `main`; final job outputs report exact counts, while deployment assumptions remain |
| Distributed rate limiting | `app/rate_limit.py`, `app/main.py`, `.github/workflows/tests.yml` | Final `rate-limit-integration` job in run 38347892406; application-level integration is included in the merged tree | Redis-backed atomic quota enforcement and fail-closed behavior are implemented and verified by 8 passed, 0 skipped Redis integration tests; production Redis operations remain a deployment responsibility |
| Local signed checkpoint comparison | `app/checkpoint.py`, `app/services/checkpoint_verifier.py` | `tests/test_checkpoints.py` | Local verification only; no external immutable trust anchor |
| Endpoint inventory and threat model | `docs/endpoint_security_inventory.md`, `docs/threat_model.md`, `tests/test_endpoint_inventory.py` | Route inventory and boundary tests | Documentation and executable inventory present |

## Known limitations and evidence boundaries

- The service uses configured API-key principals; no external identity provider is included.
- Distributed rate limiting uses the configured Redis backend and was exercised by the final `rate-limit-integration` job; Redis availability and fail-closed deployment configuration remain operational requirements.
- Checkpoints are locally verified signed objects; external publication, immutable storage, key custody, and independent detection of every valid-prefix tail truncation are not implemented.
- The project-specific Python JSON serialization format is not RFC 8785/JCS.
- PostgreSQL and Redis CI success is recorded for merged revision `ccc2db2` in workflow run `38347892406`: PostgreSQL 22 passed/0 skipped and Redis 8 passed/0 skipped, each with the existing warning. The general suite reported 253 passed/18 skipped, 1 warning, and 87.18% combined coverage. Local results are not substituted for this CI evidence.
- The final archive digest above identifies the `ccc2db2` code tree only; it does not cover this later metadata-only attestation update.
- The attestation is not itself a cryptographic signature, archive digest, or proof of independent third-party review.

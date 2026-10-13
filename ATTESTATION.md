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

- **Earlier merged `main` baseline**: `ccc2db2e2c397f8637df0bc61fcb270b3a511a46` (merge commit for PR #10, `security/p0-rate-limit-app-integration`); its CI and archive evidence are retained below as historical provenance.
- **PR #12 source revision**: `3f4e7cc79bec198b6e1965f9be80ac8eec78923b`
- **PR #12 merged `main` revision**: `8f359cf2401c3a4d5ce29a1fbff930c4006db949` (merge commit for PR #12, `security/credential-lifecycle-logging-linux-ci`).
- **PR #12 CI workflow**: [run 38359546415](https://github.com/wshal/Audit-log-service/actions/runs/38359546415), testing the exact merge commit `8f359cf2401c3a4d5ce29a1fbff930c4006db949`; `test`, `postgres-integration`, `rate-limit-integration`, and `linux-security-controls` all completed successfully.
- **PR #12 CI jobs**: [test](https://github.com/wshal/Audit-log-service/actions/runs/38359546415/job/115170221208), [postgres-integration](https://github.com/wshal/Audit-log-service/actions/runs/38359546415/job/115170220607), [rate-limit-integration](https://github.com/wshal/Audit-log-service/actions/runs/38359546415/job/115170220891), and [linux-security-controls](https://github.com/wshal/Audit-log-service/actions/runs/38359546415/job/115170220907).
- **PR #12 CI evidence boundary**: The workflow run and all four job conclusions are verified. The available unauthenticated interfaces did not expose the JUnit or coverage artifact contents, so no new exact pass/skip counts or coverage percentage are asserted for `8f359cf`; those values remain available only where the corresponding artifacts can be inspected.
- **PR #13 source revision**: `a33baf7951a351b3e6e2cab2afa08c7102ea7348` (`fix/redis-rate-limit-registry-expiry`).
- **Current merged `main` revision**: `7a46253653a6d3fcf785bac74e2082ef4f7bfe18` (merge commit for PR #13).
- **Current post-merge CI workflow**: [run 38364782044](https://github.com/wshal/Audit-log-service/actions/runs/38364782044), testing the exact merge commit `7a46253653a6d3fcf785bac74e2082ef4f7bfe18`; `test`, `postgres-integration`, `rate-limit-integration`, and `linux-security-controls` all completed successfully.
- **Current post-merge CI jobs**: [test](https://github.com/wshal/Audit-log-service/actions/runs/38364782044/job/115187181151), [postgres-integration](https://github.com/wshal/Audit-log-service/actions/runs/38364782044/job/115187180839), [rate-limit-integration](https://github.com/wshal/Audit-log-service/actions/runs/38364782044/job/115187181085), and [linux-security-controls](https://github.com/wshal/Audit-log-service/actions/runs/38364782044/job/115187181129).
- **Current post-merge CI evidence boundary**: Job conclusions and exact tested SHA are verified. Exact JUnit and coverage counts are not asserted here unless the corresponding run artifacts are independently inspected.
- **PR #15 source revision**: `3064d879081355af03a0d03a7ad339c8b2059474` (`security/supply-chain-reproducible-builds`).
- **PR #15 merged `main` revision**: `5599a32238f3a7ca798ca2187b17d0d9305d84cf`.
- **PR #15 post-merge CI workflow**: [run 38370008952](https://github.com/wshal/Audit-log-service/actions/runs/38370008952), testing the exact merged revision `5599a32238f3a7ca798ca2187b17d0d9305d84cf`. The `test`, `postgres-integration`, `rate-limit-integration`, `linux-security-controls`, `supply-chain`, and `secret-scan` jobs all completed successfully.
- **PR #15 CI artifacts**: the run uploaded `coverage-report` (`sha256:a92da57bb36b8742a9d640a4499231b106f5c897d44ff0fe24c9e6236eec480a`), `postgres-test-results` (`sha256:163c5de327d0410dc5eb81df40a0b96f61396f0093468055913ac5c48a4b613e`), `rate-limit-test-results` (`sha256:231e9fe0bbeacd03a3aba118d8ab6ed5ce2bf9a77a5b7e3bd4ef210c2fba706a`), `linux-security-test-results` (`sha256:e9525d10e945cf8da6457e8c40dd5f8fb90dd1ff7cb1ce015e1c51d0f97f4ac6`), `supply-chain-evidence` (`sha256:4bb7f38e4913c89cb2433a111579ef541faa3bceb9eb61df2feedd6ceb7cdb0f`), and `gitleaks-results.sarif` (`sha256:6cec6bd76b2c163721a25f0f06d12d54cba549419478775970c03024a2ee84a4`). The run summary reports **No leaks detected** for `secret-scan`. The accessible run page confirms artifact upload and job conclusions, but protected artifact downloads/JUnit contents were not independently readable here; no exact pass/skip counts or coverage percentage are asserted for `5599a322`.

## Dates and sign-off

- **Original development start date**: `2026-10-07`
- **Original submission date**: `2026-10-07`
- **PR #7 merge date**: `2026-10-13` (Git commit date for merge revision `d21195c7550bc747e6130b1630d7e721ffe80540`, at `00:28:07 +0530`)
- **Earlier merged `main` commit date**: `2026-10-13T10:14:15+05:30` (`ccc2db2e2c397f8637df0bc61fcb270b3a511a46`)
- **PR #12 merged `main` commit date**: `2026-10-13T12:25:49+05:30` (`8f359cf2401c3a4d5ce29a1fbff930c4006db949`)
- **PR #13 merge date**: `2026-10-13` (GitHub merge of `a33baf7` into `7a46253653a6d3fcf785bac74e2082ef4f7bfe18`)
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

The earlier merged `ccc2db2` code revision was also archived separately:

- **Artifact**: `audit-log-service-v2.0-ccc2db2-20261013.tar`
- **Source revision**: `ccc2db2e2c397f8637df0bc61fcb270b3a511a46`
- **SHA-256**: `96d190d4d7378524e3cff998a083ed2746dec5996d7ae1d73b159219b78b682c`
- **Archive size**: 747,520 bytes
- **Generation**: `git archive --format=tar --output=audit-log-service-v2.0-ccc2db2-20261013.tar ccc2db2e2c397f8637df0bc61fcb270b3a511a46`

This historical archive covers the committed `ccc2db2` tree only. It does not include
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
| Credential, request, rate-limit, idempotency, and quarantine controls | `app/credential_store.py`, `app/main.py`, `app/rate_limit.py`, `app/storage/repository.py`, `app/runtime_state.py` | Named tests in `docs/requirements_test_matrix.md`; merged-revision run 38370008952 completed the general, PostgreSQL, Redis, and Linux security jobs | Implemented in prototype scope and present in merged `main`; exact merged-run counts require artifact inspection, while deployment assumptions remain |
| Distributed rate limiting | `app/rate_limit.py`, `app/main.py`, `.github/workflows/tests.yml` | Merged-revision `rate-limit-integration` job in run 38370008952; expiry, churn, active-identity, legacy-migration, and application-level integration tests are included in the merged tree | Redis-backed atomic quota enforcement, expiry reclamation, legacy registry migration, and fail-closed behavior are implemented and CI-checked; exact current merge-run counts require artifact inspection; production Redis operations remain a deployment responsibility |
| Supply-chain locks, vulnerability audit, SBOM, and secret scanning | `requirements.lock`, `requirements-postgres.lock`, `.github/workflows/tests.yml`, `docs/supply_chain.md` | Merged-revision `supply-chain` and `secret-scan` jobs in run 38370008952 succeeded; six named evidence artifacts were uploaded and the run summary reports no leaks | Implemented and evidenced for merged `5599a322`; lockfiles do not contain artifact hashes, and the evidence does not prove vulnerability-free production images or historical-secret absence |
| Local signed checkpoint comparison | `app/checkpoint.py`, `app/services/checkpoint_verifier.py` | `tests/test_checkpoints.py` | Local verification only; no external immutable trust anchor |
| Endpoint inventory and threat model | `docs/endpoint_security_inventory.md`, `docs/threat_model.md`, `tests/test_endpoint_inventory.py` | Route inventory and boundary tests | Documentation and executable inventory present |

## Known limitations and evidence boundaries

- The service uses configured API-key principals; no external identity provider is included.
- Distributed rate limiting uses the configured Redis backend and was exercised by the post-merge `rate-limit-integration` job in run `38370008952`; Redis availability and fail-closed deployment configuration remain operational requirements.
- Checkpoints are locally verified signed objects; external publication, immutable storage, key custody, and independent detection of every valid-prefix tail truncation are not implemented.
- The project-specific Python JSON serialization format is not RFC 8785/JCS.
- Historical PostgreSQL, Redis, and general-suite counts above are evidence for merged revision `ccc2db2` in workflow run `38347892406`; they are not counts for the current `5599a322` merge run. The current run's six job successes, tested SHA, artifact names, and artifact digests are verified from run `38370008952`, but exact JUnit pass/skip counts and coverage are not asserted because protected artifact contents were not independently readable.
- The historical archive digest above identifies the `ccc2db2` code tree only; it does not cover this later metadata-only attestation update or the later `8f359cf`, `7a462536`, and `5599a322` merge commits.
- The attestation is not itself a cryptographic signature, archive digest, or proof of independent third-party review.

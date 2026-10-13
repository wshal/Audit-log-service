# Audit Log Service threat model

## Assets and trust boundaries

- Audit records, hash-chain state, V1/V2 transition evidence, signatures, lifecycle manifests, idempotency results, and checkpoint material are integrity-sensitive.
- API credentials, signing keys, checkpoint keys, database credentials, and recovery authority data are secrets or authority material.
- The application process, database, filesystem authority directory, deployment proxy, CI service, and any external checkpoint store are separate trust boundaries. This repository only controls the application/database portions and documents deployment assumptions for the others.

## Threats and controls

| Threat | Implemented control | Evidence / limitation |
|---|---|---|
| Unknown, expired, revoked, malformed, or unavailable credentials | Credential manifest validation, lifecycle states, fail-closed authority errors, secret-redacted authentication events | `app/credential_store.py`, `app/security.py`, credential tests; deployment filesystem ownership and rotation operations still require operational enforcement |
| Cross-tenant or cross-resource BOLA | Authenticated principal grants, resource ownership resolution, repository predicates, non-disclosure of unauthorized counts/selectors | `app/authorization.py`, repository/services, `tests/test_tenant_authorization.py`; deployment identity provisioning is outside the repo |
| Forged actor or proxy attribution | Actor binding to authenticated subject; explicit proxy role and non-empty delegation reason | Authorization and repository direct-call tests; administrator role alone is not delegation |
| Replay and duplicate submission | Scoped idempotency key/fingerprint records, unique constraints, concurrent conflict handling, unknown-commit response | `app/storage/repository.py`, idempotency tests, PostgreSQL integration; external client retry behavior remains an operational concern |
| Request flooding and oversized input | Shared Redis-backed authenticated/anonymous limiter and 256 KiB request-body guard | `app/rate_limit.py`, `app/main.py`, endpoint and Redis integration tests; production Redis is required and outage fails closed |
| Hash, signature, deletion, reordering, or transition tampering | Ed25519 signatures, hash chaining, ledger-state verification, startup preflight/quarantine, V1/V2 transition checks | Integrity, migration, recovery, and PostgreSQL tests; valid signed-prefix tail truncation needs an independently retained checkpoint |
| Checkpoint substitution or stale local history | Versioned checkpoint schema, trusted-key signature verification, local full-ledger verification before comparison | `app/checkpoint.py`, `app/services/checkpoint_verifier.py`; no external immutable publication or custody service |
| Sensitive logging or PII leakage | Sanitized authentication messages, scoped exports/compliance projection, separate PII capability, request/error response minimization | Security, export, and compliance tests; production log sink/redaction configuration remains deployment-dependent |
| TLS/proxy abuse | No application-level TLS termination or proxy trust policy is claimed | TLS, forwarded-header policy, firewalling, and network segmentation must be configured and verified in deployment |
| Dependency or supply-chain vulnerability | Declared dependencies and reproducible CI installation | CI runs tests/coverage/compile; no complete dependency vulnerability scan is configured |
| Database compromise or restore rollback | Database constraints, transactional allocator, migration validation, rollback tests | PostgreSQL/SQLite tests; backups, restore drills, external checkpoints, and multi-host recovery remain unverified |

## Security assumptions requiring deployment evidence

1. Production API keys are provisioned through the credential authority and are not left in source, URLs, or logs.
2. The signing private key and checkpoint trust material are stored outside the database with restrictive ownership and rotation procedures.
3. TLS terminates at a trusted proxy or application boundary; proxy headers cannot be forged by clients.
4. The database account has only the required schema/data privileges and backups are protected from the application writer.
5. Production instances use one shared Redis limiter namespace. Redis provisioning, access controls, capacity, failover, centralized security logging, and an independently retained checkpoint remain deployment responsibilities.

## Residual risks

- A compromised service with valid signing authority can create internally valid new history; external key custody and checkpoints are required for stronger provenance.
- A valid signed prefix can be truncated without detection when no independent checkpoint covers the removed suffix.
- Redis-backed quotas constrain aggregate abuse across configured workers/hosts; Redis availability, namespace isolation, capacity, and failover remain operational assumptions.
- Idempotency does not replace authentication, authorization, or a client-side durable retry policy.

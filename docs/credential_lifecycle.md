# Credential lifecycle boundary

The service retains the `X-API-Key` interface. When
`AUDIT_CREDENTIAL_MANIFEST` is set, authentication reads that operator-managed
manifest for every request. The manifest stores only SHA-256 digests and
non-secret principal metadata; plaintext keys are delivered out of band once
and are never persisted or logged.

Each credential is `staged`, `active`, `revoked`, or `superseded`; an `active` credential
whose `expiresAt` is in the past is treated as `expired`. Malformed, missing,
unreadable, or conflicting manifests are authentication infrastructure failures
and return HTTP 503. Unknown, malformed, expired, revoked, and superseded
credentials return generic HTTP 401 responses. No stale environment or
process-local manifest fallback is used when a manifest path is configured.

The prototype bounds authority collections before authentication or authorization
consumes them: a manifest may contain at most 256 credentials; each credential
may have 16 roles and 64 tenant grants; each grant may contain 16 actions and 64
resource scopes; and each resource list may contain 256 identifiers. These are
resource-safety limits, not authorization wildcards or truncation rules.
Oversized collections fail closed with HTTP 503, and lifecycle-created
provisioning or staged-rotation entries are validated against the same limits.

Provisioning, rotation, and revocation are operator procedures, not API
routes. The helper operations in `app.credential_store` are intended to run
under a separately authenticated OS identity. All read-modify-write operations
use a persistent sibling lock file with a bounded five-second acquisition:
POSIX uses `fcntl.flock`; Windows uses one-byte `msvcrt.locking`. The lock file
is never deleted. Process termination releases the OS lock, but network filesystems
and lock-file replacement are outside the supported boundary.

Manifest replacement uses complete write, flush, file fsync, atomic replacement,
and containing-directory fsync where supported. The service identity must be
read-only for the manifest and its parent directory. The repository does not
establish those ACLs itself; production readiness therefore depends on
deployment verification.

Rotation is staged first: the replacement is `staged` and cannot authenticate.
The operator delivers the plaintext once, records an explicit delivery
acknowledgement, and then calls activation. Activation marks the old version
`superseded` and the replacement `active` in one manifest replacement. Before
activation, the old credential remains valid. Revocation is visible to every
request after the replacement is committed because authorization decisions are
not cached. A failure before replacement leaves the prior manifest
authoritative. A failure after replacement but before directory durability is
confirmed is an ambiguous outcome; it must not be described as a rollback and
requires operator inspection/reconciliation. The token was eligible for
activation only after delivery acknowledgement. Operational authentication logs, if enabled by deployment,
must contain only outcome categories, credential IDs known after validation,
and request metadata; they must never contain API keys, digests, headers, or
manifest contents.

## Administrative Lifecycle Logging and Operational Monitoring

The administrative lifecycle helpers in `app.credential_store` emit structured, sanitized security events to logger `audit.security.credentials` for operator traceability:

- **Lifecycle Actions**: `credential_provisioned`, `credential_rotated`, `credential_delivery_acknowledged`, `credential_activated`, `credential_revoked`, and `operator_lock`.
- **Outcome Categories**: `success`, `already_active`, or specific bounded failure categories (`failed_validation`, `failed_duplicate_identifier`, `failed_target_not_active`, `failed_not_staged`, `failed_not_acknowledged`, `failed_not_found`, `failed_timeout`, `failed_unavailable`, `failed_persistence`, `ambiguous_persistence`, `failed_unconfigured`).
- **Sanitized Identifiers**: `credential_id`, `subject`, `replacement_id`, and `lock_target` are strictly sanitized to strip control characters and newlines (`[\x00-\x1f\x7f-\x9f]` mapped to `_`), bounding length to prevent log-injection or newline-splitting attacks.
- **Strict Data Exclusion**: Plaintext tokens, secret keys, SHA-256 digests, authorization headers, raw manifest JSON documents, and untrusted exception messages are strictly forbidden from log output.

### Distinction: Operational Application Logs vs Tamper-Evident Ledger
Operational application logs recorded via `audit.security.credentials` serve operational monitoring, alerting, and local diagnostics. They are **not** an append-only, cryptographically verified data store. They do not replace, alter, or substitute for the immutable hash-chained audit ledger maintained by the Audit Log Service.

## Platform Locking Verification and CI

Cross-process mutual exclusion relies on native OS file locking:
- **Linux / POSIX**: Employs `fcntl.flock` with non-blocking exclusive acquisition (`LOCK_EX | LOCK_NB`) and explicit release (`LOCK_UN`).
- **Windows**: Employs `msvcrt.locking` with non-blocking single-byte locking (`LK_NBLCK`, `LK_UNLCK`).

In GitHub Actions CI (`.github/workflows/tests.yml`):
- Windows CI (`test` job on `windows-latest`) tests the entire application stack under Windows file locking and verifies line/branch coverage thresholds (>= 85%).
- Linux CI (`linux-security-controls` job on `ubuntu-latest`) executes `tests/test_security_controls.py` on Linux, enforcing zero skips and explicitly asserting native POSIX `fcntl.flock` execution.

Without a configured manifest, development retains the historical built-in
development key and explicit `AUDIT_API_KEYS` compatibility behavior. Production
must configure `AUDIT_CREDENTIAL_MANIFEST`; otherwise authenticated requests
return HTTP 503. This local-manifest design does not provide an independent
identity provider, external key custody, or a guarantee beyond the host
filesystem permissions and operator procedures.

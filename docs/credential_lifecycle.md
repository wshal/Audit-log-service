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

Without a configured manifest, development retains the historical built-in
development key and explicit `AUDIT_API_KEYS` compatibility behavior. Production
must configure `AUDIT_CREDENTIAL_MANIFEST`; otherwise authenticated requests
return HTTP 503. This local-manifest design does not provide an independent
identity provider, external key custody, or a guarantee beyond the host
filesystem permissions and operator procedures.

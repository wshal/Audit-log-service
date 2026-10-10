# Phase 1B V2 protocol decision

V1 remains an immutable legacy epoch. It is not assigned a tenant and is never
rewritten. V2 remains in the current table for this phase to avoid a destructive
data move, uses a distinct protocol marker, and is verified as a separate
protocol epoch while retaining the existing global sequence for append ordering.

Each V2 canonical envelope binds event content, tenant ownership, authenticated
subject, credential ID, attribution mode, delegation reason, and protocol
version. The existing V1 envelope is unchanged.

The signed transition records the V1 count and final tip, the first V2 global sequence
and record hash, cutover timestamp, and protocol versions. Verification compares
the transition to the actual rows before verifying V2. Missing, malformed,
reordered, truncated, or modified transition evidence fails closed. A validly
signed tail truncation cannot be detected without an independently retained
checkpoint; that limitation is explicit.

The first V2 append and its transition are committed in one transaction. A
failure in signing or persistence rolls back both. Existing V1 records remain
byte-for-byte unchanged; unknown legacy ownership remains unknown.

Acceptance criteria: attribution-field mutation fails verification; V1-only and
mixed ledgers verify with their respective protocols; transition fields are
checked against actual database state; transition deletion/tampering fails;
fresh and legacy migrations are idempotent and fail closed on inconsistent
legacy state; and authorized lifecycle operations are tenant/resource scoped.

At startup, schema migration runs first, followed by a read-only integrity
preflight. The service states are `uninitialized`, `validating`, `healthy`, and
`quarantined`. A failed or indeterminate preflight writes an operator-visible
quarantine marker, keeps liveness available, returns minimal unhealthy health
information, and blocks all `/audit` routes plus readiness. The marker is
atomically replaced and persists on the configured local filesystem; directory
fsync is best-effort where unsupported. Restart does not clear it. Recovery
requires a one-time `AUDIT_QUARANTINE_RECOVERY_TOKEN`; its hash and outcome are
persisted, so leaving the token configured cannot authorize a later restart.
The token is consumed before validation and the marker is removed only after
successful preflight. Nested object and array PII fields are recursively
projected unless the caller has `pii_reader`.

Recovery consumption uses an exclusive file-create reservation (`O_CREAT |
O_EXCL`) on the configured marker filesystem. This provides single-use
semantics across processes sharing that filesystem. It does not provide a
distributed multi-host lock when workers use different local or ephemeral
volumes; production deployments must place the marker and reservation on a
shared durable filesystem or provide an equivalent external lock.
The consumed reservation must remain readable and well-formed before an
outcome is recorded. Missing, malformed, unreadable, or failed outcome
persistence is fail-closed: the quarantine marker is retained and the service
does not become ready. Outcome updates use a same-directory temporary file,
flush/fsync, atomic replacement, and directory fsync where supported. A
filesystem that cannot durably flush directory entries is an explicit
deployment limitation, not a successful recovery guarantee.
Initial reservation creation applies the same file flush/fsync and containing
directory fsync sequence before validation begins. Unsupported directory fsync
is reported as an unsupported capability; actual open or fsync errors fail the
attempt and retain quarantine. Process-interruption tests cover exits before
outcome persistence and after outcome persistence but before marker removal;
both restart paths remain quarantined and cannot reuse the consumed token.

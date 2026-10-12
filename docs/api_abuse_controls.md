# API abuse controls

The service applies a bounded process-local fixed-window limiter to `/audit`
requests. Before authentication, requests are counted by the transport client
address. After authentication, requests are additionally counted by the
authenticated credential identity and operation path. Caller-supplied identity
headers and API-key material are never used as limiter keys or emitted in
responses/logs.

Configuration:

- `AUDIT_RATE_LIMIT_CAPACITY` (default `1000` requests per window)
- `AUDIT_RATE_LIMIT_WINDOW_SECONDS` (default `60`, bounded to one day)
- `AUDIT_RATE_LIMIT_MAX_KEYS` (default `4096`, bounded to `100000`)

Exceeding a limit returns HTTP 429 with a generic response. Entries are bounded
with oldest-key eviction and expire when their window rolls over. This is a
per-process control only. The supported deployment contract for this prototype
is one application process and one service replica; do not start
Uvicorn/Gunicorn with multiple workers or deploy multiple replicas while
relying on this limiter. A deployment that needs aggregate enforcement must
choose and operate a shared backend before claiming a global quota.

The application cannot reliably discover the effective worker count or replica
count from inside the ASGI process. Operators must validate the deployment
configuration and runtime process/replica count as part of release checks
(for example, inspect the server command, container replica setting, and
process list). No startup guard is claimed to prevent an operator from
misconfiguring a multi-process deployment.

`POST /audit/events` accepts an `Idempotency-Key` matching
`[A-Za-z0-9._~-]{16,128}`. Keyed requests require an explicit timestamp. The
key is scoped to the authenticated credential, tenant (or `__legacy__` V1
scope), method, and endpoint. A canonical request fingerprint prevents reuse
with different data (`409`); successful replays return the original record with
HTTP 200 and `Idempotent-Replay: true`. The idempotency row, audit record, and
ledger-state update share one database transaction. Records are retained for
24 hours by default and may be removed by the bounded maintenance cleanup;
reusing an expired key can create a new append.

Cleanup must run from an idle, dedicated maintenance session. It refuses a
caller-owned active transaction and never commits unrelated pending work. The
idempotency migration has no routine destructive downgrade; operators must use
an explicitly reviewed recovery procedure rather than dropping result records
and reopening replayable keys.

The idempotency implementation uses the same SQLite `BEGIN IMMEDIATE` or
PostgreSQL ledger-state row lock as ordinary appends. A commit/connection
failure remains ambiguous to the caller, but a later authenticated retry first
looks up the durable scoped result and never blindly appends a duplicate.

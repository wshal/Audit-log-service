# API abuse controls

The service applies an atomic fixed-window limiter to `/audit` requests. In
production, it requires the configured Redis-compatible backend so all workers
and replicas share quota state. Before authentication, requests are counted by
the transport client address. After authentication, requests are additionally
counted by the authenticated credential identity and operation path.
Caller-supplied identity headers and API-key material are never used as limiter
keys or emitted in responses/logs.

Configuration:

- `AUDIT_RATE_LIMIT_CAPACITY` (default `1000` requests per window)
- `AUDIT_RATE_LIMIT_WINDOW_SECONDS` (default `60`, bounded to one day)
- `AUDIT_RATE_LIMIT_MAX_KEYS` (default `4096`, bounded to `100000`)
- `AUDIT_RATE_LIMIT_BACKEND` (`memory` outside production; `redis` is required
  in production)
- `AUDIT_RATE_LIMIT_REDIS_URL` (required when the Redis backend is selected)
- `AUDIT_RATE_LIMIT_REDIS_PREFIX` (default `audit:ratelimit:v1`)
- `AUDIT_RATE_LIMIT_REDIS_TIMEOUT_SECONDS` (default `0.5`, bounded to `10`)
- `AUDIT_RATE_LIMIT_REDIS_MAX_CONNECTIONS` (default `16`, bounded to `256`)
- `AUDIT_RATE_LIMIT_REQUIRED=1` (integration-test guard that fails if Redis is
  unavailable)

Exceeding a limit returns HTTP 429 with a generic response and `Retry-After`.
Redis counters are updated by one atomic Lua operation and expire at the end of
the configured window. The `memory` backend remains an explicit local-
development/test option. In production, a missing, invalid, or unavailable
Redis backend returns a bounded generic HTTP 503; the service never silently
falls back to process-local enforcement.

All instances intended to enforce one quota must use the same Redis URL and
namespace. Operators must provision Redis, restrict its access, monitor
capacity/latency, and validate the configured namespace during release checks.
The application does not provision Redis or claim a managed Redis service,
high-availability failover, or cross-region clock guarantees.

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

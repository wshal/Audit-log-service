# Endpoint security inventory

This inventory describes the registered `/audit` API on the current source tree. The executable route inventory is maintained by `tests/test_endpoint_inventory.py`; endpoint authorization is enforced by router dependencies and service/repository boundaries.

| Method and path | Authentication / roles | Tenant and resource scope | Input and abuse boundary | State change and integrity controls | Evidence |
|---|---|---|---|---|---|
| `POST /audit/events` | API key; `writer`; authenticated rate limit | Tenant/resource grant, trusted principal actor binding, explicit proxy delegation; legacy writes require explicit legacy capability | Pydantic event validation, 256 KiB body middleware, idempotency-key syntax/fingerprint | Appends hash/signature-bound record; database allocator; idempotent replay/unknown-commit handling | `app/routers/audit.py`, `app/storage/repository.py`, tenant/idempotency/security tests |
| `GET /audit/events` | API key; `reader`; authenticated rate limit | Tenant/resource predicates are applied in repository queries; ambiguous tenant lists fail closed | Query validation, bounded `limit`/offset, body limit middleware | Read-only; no disclosure of unauthorized counts/pagination | `app/routers/audit.py`, `tests/test_tenant_authorization.py` |
| `GET /audit/verify` | API key; `global_auditor`; authenticated rate limit | Global integrity policy; no ordinary tenant-wide verification | Queryless endpoint; body boundary still applies | Full chain, signatures, transitions, ledger state, and quarantine/readiness rules | `app/services/verifier.py`, integrity and authorization tests |
| `GET /audit/export` | API key; `exporter`; authenticated rate limit | Resource-scoped grants for tenant principals; legacy export policy is explicit; PII is separately controlled | Required actor/resource selector; query validation and body limit | Read-only export with lifecycle witnesses and bundle hash; no global inclusion proof | `app/routers/lifecycle.py`, `app/services/lifecycle.py`, export tests |
| `GET /audit/compliance/client-access` | API key; `compliance_reviewer`; authenticated rate limit | Client resolves to a tenant and is authorized before query; PII capability is separate | Required `clientId`; time/actor filters validated; body limit | Read-only minimized compliance projection; no arbitrary payload by default | `app/routers/compliance.py`, `app/services/compliance.py`, compliance tests |
| `POST /audit/redact` | API key; `privacy_officer`; authenticated rate limit | Service checks record/resource authorization and tenant scope | Pydantic field paths/reason; body limit | Redaction commitments preserve chain semantics; denial is non-mutating | `app/routers/lifecycle.py`, lifecycle/authorization tests |
| `POST /audit/retention/apply` | API key; `retention_admin`; authenticated rate limit | Tenant retention requires a resolved resource grant; legacy path is explicit | Pydantic retention request and body limit | Archive/lifecycle manifest updates are transactional and authorization-scoped | `app/routers/lifecycle.py`, lifecycle/authorization tests |
| `GET /health` | Public liveness endpoint | No ledger data | No application payload | No state change | `app/main.py`, endpoint tests |
| `GET /ready` | Public readiness status | Exposes readiness state only | No application payload | Reflects startup integrity/quarantine state | `app/main.py`, preflight/quarantine tests |

## Cross-cutting controls and assumptions

- `X-API-Key` authentication is fail-closed in production when the configured authority is missing or unavailable. Credentials, digests, and secrets are not intended for logs or responses.
- The application request guard rejects bodies above 256 KiB; a deployment proxy should enforce a compatible limit as defense in depth.
- TLS termination, trusted proxy configuration, firewalling, database credentials, filesystem ACLs, key custody, backup/restore, dependency scanning, and log retention remain deployment responsibilities.
- Production rate limiting uses the shared Redis-compatible backend; memory mode is limited to explicit local development/test use. Missing or unavailable production Redis fails closed with HTTP 503.
- The checkpoint implementation is deliberately not an external trust anchor or checkpoint publication service.

## Evidence gaps

- The endpoint inventory proves route registration and selected negative boundaries; it does not replace a production deployment review.
- No external identity provider, managed Redis service/failover, external checkpoint store, key-rotation custody workflow, or independently retained archive checkpoint is configured by this repository.
- PR #7 workflow and job success are revision-bound evidence, but detailed job test counts were not independently retrievable during this update.

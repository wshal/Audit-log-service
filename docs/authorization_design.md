# P0 Authorization Design: Tenant-Scoped V2 Ledger

**Status:** Approved design; Phase 1B remediation implemented, independent review pending.  
**Scope:** SEC-03/BOLA and TEST-04 only. This document does not introduce an external identity provider, distributed infrastructure, or unrelated production hardening.

Startup integrity is enforced separately from authorization: schema migration is
followed by a read-only V1/V2 preflight. Corruption or indeterminate verification
places the service in persistent quarantine; audit routes and readiness are
blocked until a repaired database passes preflight using a one-time
`AUDIT_QUARANTINE_RECOVERY_TOKEN`. Health responses never expose ledger
payloads, hashes, credentials, or customer data.

## Authorization policy

Authorization is **default deny** and requires all three checks:

1. The credential authenticates to a `Principal` with a stable `credentialId`, `subject`, roles, and explicit grants.
2. The requested operation is allowed by a role.
3. The requested object is within a matching tenant and resource grant.

Roles are operation permissions; they never bypass object authorization. In particular, `admin` is configuration-only and has no implied cross-tenant, PII, proxy, read, or write access.

Each configured principal uses the existing `AUDIT_API_KEYS` mechanism, extended with `credentialId` and explicit `tenantGrants`. A grant lists a tenant, allowed actions (`read`, `write`, `export`, `compliance`, `redact`, `retain`), and permitted `(resourceType, resourceId)` scopes. A server-owned resource registry maps each resource to its tenant and classification. Request-provided tenant, actor, client, and resource identifiers are selectors only; they are never authorization proof.

Unknown resources fail closed. Normal users cannot create an event for an unregistered resource. A separately trusted registration process creates resource ownership records after out-of-band approval; an ownership change creates a new effective-dated ownership record and never changes the tenant recorded in historical audit events.

## Endpoint policy and non-disclosure behavior

| Endpoint | Required role and grant | Object policy | Denial/non-disclosure behavior |
|---|---|---|---|
| `POST /audit/events` | `writer` + `write` scope | Server resolves resource owner; it must match the principal grant. | `403`; no record/manifests are written. |
| Proxy append | `writer`, `audit_proxy`, and `write` scope | Same resolution; non-empty delegation reason required. | `403` for absent proxy/scope; `422` for malformed delegation; no write. |
| `GET /audit/events` | `reader` + `read` scope | Tenant selector required; scope predicates are applied in the repository before filters, count, order, and pagination. Payload needs `pii_reader` or is safely projected. | An ungranted tenant yields `403`; inaccessible direct object lookup yields `404`; list totals/items/page metadata include authorized rows only. |
| `GET /audit/verify` | `global_auditor` only | No tenant-filtered verification of the global chain. | `403`; no sequence/count/break metadata. |
| `GET /audit/export` | `exporter` + `export` scope; `pii_reader` for unredacted payload | Require tenant selector plus actor or resource filter; apply scope before loading records or deriving bundle metadata. | `403` for ungranted tenant; inaccessible direct resource is `404`; no counts, bounds, keys, manifests, or bundle hash for unauthorized rows. |
| `GET /audit/compliance/client-access` | `compliance_reviewer` + `compliance` scope; `pii_reader` for payload | Resolve the client resource in the registry and require exact permitted scope. | `404` for unknown/inaccessible client; no report totals, actor summaries, anomalies, or PII leak. |
| `POST /audit/redact` | `privacy_officer` + `redact` scope | Find by `sequence_num AND tenant_id`, then authorize its resource. | `404` for a record outside caller scope; no redaction/lifecycle manifest. |
| `POST /audit/retention/apply` | `retention_admin` + `retain` scope | Tenant selector is required; selection query is tenant-constrained before archival. | `403`; no archive state/manifests are written. |

## Attribution

For an ordinary writer, `actorId` must equal `principal.subject`. Every V2 event hash binds both the business actor and the authenticated caller:

```text
tenantId, actorId, authenticatedSubject, credentialId, attributionMode,
eventType, resourceType, resourceId, payload, timestamp, protocolVersion
```

A proxy caller needs the explicit `audit_proxy` role and matching write scope. It may name a different business actor only with a non-empty `delegationReason`. The record contains `attributionMode=PROXY`, `authenticatedSubject`, `credentialId`, and `delegationReason`; this preserves the actual caller’s accountability. `admin` alone cannot impersonate an actor.

## Epoch and legacy V1 policy

V1 has no tenant field. It remains a frozen, read-only legacy epoch: its original bytes, hashes, signatures, sequences, and V1 verifier stay unchanged. No tenant will be inferred or backfilled.

Only `global_auditor` can access legacy records; legacy payload access additionally requires `legacy_pii_reader`. Tenant-scoped users cannot query, export, redact, retain, or receive compliance reports for V1 records. Privacy or retention requests concerning V1 are handled by an approved external process and a separately recorded case reference; this service does not silently mutate V1 history.

V2 is a separate protocol epoch represented by non-null tenant and attribution fields in the current table. Its signed transition evidence contains the final V1 count and tip hash, first V2 sequence and record hash, cutover timestamp, protocol version, and a signature over canonical transition content. It does not rewrite V1. A future deployment may move V2 to a physically separate table/sequence space.

## Global verification

`global_auditor` verification performs three ordered checks:

1. Verify V1 using its original V1 hashing/signature rules.
2. Verify the signed transition evidence against the verified V1 final state.
3. Verify V2 using the V2 tenant-bound content hash, record chain, lifecycle manifests, and signatures.

The response exposes aggregate epoch status and only the first relevant broken location to `global_auditor`; it does not grant payload access. Tenant verification is deliberately not claimed: a filtered tenant view cannot verify a global predecessor chain without a separate per-tenant chain or privacy-preserving inclusion proof.

Required transition tests include tampering V1 content, tampering the V1 tip referenced by transition evidence, tampering any transition field/signature, V2 tenant/content mutation, and a valid V1-to-V2 verification flow.

## Required test plan

Tests use two tenants and ordinary restricted credentials, not the development admin key:

- Tenant A cannot query, export, redact, retain, or obtain compliance results for Tenant B.
- A Tenant A principal cannot access an ungranted Tenant A resource.
- Direct identifiers, totals, pagination, export bounds, integrity manifests, and compliance metadata reveal only authorized records.
- Ordinary writers cannot spoof actors; authorized proxies preserve caller attribution and reason.
- Unauthorized operations leave both event tables and lifecycle manifests unchanged.
- V1/V2/global transition verification detects tampering in either epoch or transition evidence.
- V2 tenant-bound content mutation fails V2 verification.
- Existing valid V1 integrity/redaction/retention/export tests remain valid or are explicitly reclassified to the V1 compatibility suite.

## Implementation order

Before authorization work, tests move from a shared repository-path SQLite database to a fresh `tmp_path` database per test, with the application lifespan, dependency override, auth configuration, and signing-key path all bound to that same fixture. The suite must pass five consecutive fresh runs.

After that baseline is proven, authorization changes occur on `security/tenant-authorization-p0`: failing authorization tests first; principal/grant and resource-registry models; V2 epoch schema and protocol; repository-level scope predicates; endpoint policy; lifecycle binding; global epoch verification; then migration/legacy documentation. No unrelated credential-lifecycle, PostgreSQL, or external-checkpoint implementation is included.

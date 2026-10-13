# Manual End-to-End Validation Guide

Use this clean-database walkthrough to validate Scenario A (core ledger), Scenario B (redaction, retention, export), Scenario C (compliance), signatures, and authorization.

## Start a clean local instance

Open PowerShell in the repository root. This keeps the existing `audit_ledger.db` untouched and uses an ignored demo database.

```powershell
$env:DATABASE_URL = "sqlite:///local_data/manual_demo.db"
$env:AUDIT_ENV = "development"
Remove-Item -LiteralPath ".\local_data\manual_demo.db" -ErrorAction SilentlyContinue
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000
```

Leave it running. In a second PowerShell window:

```powershell
$headers = @{ "X-API-Key" = "development-only-audit-key"; "Content-Type" = "application/json" }
$base = "http://127.0.0.1:8000"
```

The development key has `admin` privileges and is only for local use.

## Scenario A: append, query, verify

```powershell
$events = @(
  @{ eventType="ACCOUNT_VIEWED"; actorId="advisor-lena"; resourceType="CLIENT_ACCOUNT"; resourceId="client-demo"; payload=@{ justification="PORTFOLIO_REVIEW"; clientConsent=$true; ssn="123-45-6789" }; timestamp="2026-10-01T09:00:00Z" },
  @{ eventType="HOLDINGS_EXPORTED"; actorId="advisor-lena"; resourceType="CLIENT_ACCOUNT"; resourceId="client-demo"; payload=@{ justification="TAX_FILING_PREP"; exportFormat="PDF" }; timestamp="2026-10-01T09:30:00Z" },
  @{ eventType="ACCOUNT_VIEWED"; actorId="intern-sam"; resourceType="CLIENT_ACCOUNT"; resourceId="client-demo"; payload=@{ viewedFields=@("taxId") }; timestamp="2026-10-01T10:00:00Z" },
  @{ eventType="LOGIN"; actorId="retention-service"; resourceType="SYSTEM"; resourceId="old-record"; payload=@{}; timestamp="2020-01-01T00:00:00Z" }
)
$events | ForEach-Object { Invoke-RestMethod "$base/audit/events" -Method Post -Headers $headers -Body ($_ | ConvertTo-Json -Depth 10) }
Invoke-RestMethod "$base/audit/events?actorId=advisor-lena&resourceId=client-demo" -Headers $headers | ConvertTo-Json -Depth 10
Invoke-RestMethod "$base/audit/verify" -Headers $headers | ConvertTo-Json
```

Expected: four created records with `sequenceNum` 1–4, each with a 64-character `recordHash`, a non-empty `recordSignature`, and `signingKeyId: "development-local"`. The query has `total: 2`. Verification is:

```json
{"intact":true,"recordsVerified":4,"violationType":"NONE"}
```

Hashes, signatures, IDs, and `verifiedAt` vary per run.

## Scenario B: redact, retain, export

```powershell
Invoke-RestMethod "$base/audit/redact" -Method Post -Headers $headers -Body (@{ sequenceNum=1; fieldPaths=@("ssn"); reason="Approved privacy request" } | ConvertTo-Json)
Invoke-RestMethod "$base/audit/retention/apply" -Method Post -Headers $headers -Body (@{ retentionDays=365; reason="Approved retention policy" } | ConvertTo-Json)
Invoke-RestMethod "$base/audit/verify" -Headers $headers | ConvertTo-Json
Invoke-RestMethod "$base/audit/export?resourceId=client-demo" -Headers $headers | ConvertTo-Json -Depth 12
(Invoke-RestMethod "$base/audit/events?resourceId=client-demo" -Headers $headers).items[0].payload
```

Expected: redaction confirms `sequenceNum: 1`; retention returns `recordsArchived: 1` and `archivedSequenceNumbers: [4]`; verification returns `intact: true`, `recordsVerified: 6`, and `violationType: "NONE"`. Records 5 and 6 are signed lifecycle manifests. The export has `totalRecords: 3`, a 64-character `bundleIntegrityHash`, a non-empty `signingPublicKeys` map, and one `integrityManifests` entry with `eventType: "AUDIT_RECORD_REDACTED"`. The queried SSN starts with `[REDACTED:COMMITMENT:`.

## Scenario C: compliance report

```powershell
Invoke-RestMethod "$base/audit/compliance/client-access?clientId=client-demo" -Headers $headers | ConvertTo-Json -Depth 12
```

Expected keys: `clientId: "client-demo"`, `totalAccessEvents: 3`, `chainIntegrityVerified: true`, and `complianceStatus: "FLAGGED_FOR_REVIEW"`. `anomaliesDetected` names `intern-sam` because that access deliberately omits a justification. `advisor-lena` has two accesses and `intern-sam` has one.

## Authorization negative check

```powershell
Invoke-WebRequest "$base/audit/verify" -SkipHttpErrorCheck | Select-Object StatusCode, Content
```

Expected: HTTP `401` because no API key was sent.

## Automated equivalent

Stop the service with `Ctrl+C`, then run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The earlier PostgreSQL-unconfigured working-tree result was **249 passed, 12
skipped**. With the guarded PostgreSQL environment configured, the latest
current working-tree result is **261 passed, 0 skipped** (plus one dependency
deprecation warning). The current PostgreSQL 16.15 suite completed **22 passed,
zero skipped, 1 warning** against `audit_test`. A focused
endpoint/integrity/security run completed with **99 passed, 1 warning**; the
warning is the existing Starlette/httpx deprecation warning. Compilation and
`git diff --check` passed. These results apply to the current uncommitted tree;
the combined flow is
`test_end_to_end_ideal_workflow` in `tests/test_security_controls.py`; tenant
authorization coverage is in `tests/test_tenant_authorization.py`, and startup
quarantine/direct-entry/recovery coverage is in `tests/test_preflight_quarantine.py`.

For reproducible coverage and compile validation, run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q --cov=app --cov-branch --cov-report=term-missing --cov-report=xml --cov-fail-under=85
.\.venv\Scripts\python.exe -m compileall -q app tests
```

The earlier measured run is historical: 91.08% line coverage, 78.76% branch
coverage, and 88.27% combined coverage. A prior local coverage command
measured 88.02% combined coverage (the configured 85% gate passed). This
coverage result is historical for an earlier working tree; coverage was not
rerun for the latest validation.
The default and coverage commands above do not configure PostgreSQL; the
database-backed tests are separately selectable under `tests/postgres`. The
integration suite is under `tests/postgres`. The
PR #7 [workflow](https://github.com/wshal/Audit-log-service/actions/runs/38293842786)
and [postgres-integration job](https://github.com/wshal/Audit-log-service/actions/runs/38293842786/job/114960061221)
completed successfully for source revision `76e93211137e02d222d320757dab8a5e1f635bbc`,
which is included in merged `origin/main` revision
`d21195c7550bc747e6130b1630d7e721ffe80540`. Detailed CI test counts were not
independently available in this review, so they are not inferred here.

To execute the PostgreSQL suite locally without placing credentials in a URL,
use the dedicated password file and guarded test database:

```powershell
$env:PGPASSFILE = "$env:APPDATA\postgresql\pgpass.conf"
$env:POSTGRES_TEST_DATABASE_URL = "postgresql+psycopg://audit@localhost:5432/audit_test"
$env:POSTGRES_TEST_REQUIRED = "1"

try {
    .venv\Scripts\python -m pytest tests/postgres -q -rs
} finally {
    Remove-Item Env:PGPASSFILE -ErrorAction SilentlyContinue
    Remove-Item Env:POSTGRES_TEST_DATABASE_URL -ErrorAction SilentlyContinue
    Remove-Item Env:POSTGRES_TEST_REQUIRED -ErrorAction SilentlyContinue
}
```

The PostgreSQL run uses a password file outside the repository and the guarded
local `audit_test` database. It does not substitute for CI validation on a
final committed revision.

The Phase B checkpoint contract is exercised by `tests/test_checkpoints.py`.
`app/checkpoint.py` validates the versioned signed object, and
`app/services/checkpoint_verifier.py` invokes the authoritative full-ledger
verifier before returning `MATCHING_PREFIX` or `UNANCHORED_SUFFIX`. These
results do not provide external storage immutability or prove completeness
beyond the trusted checkpoint sequence. External publication and retention
remain unimplemented.

For idempotent appends, send an `Idempotency-Key` header (16–128 safe ASCII
characters) and an explicit timestamp. The first `POST /audit/events` returns
201; an identical retry returns 200 with `Idempotent-Replay: true`; reusing the
key with a different request returns 409. The key scope and result are stored
atomically with the ledger append. Expired keys are reusable after explicit
maintenance cleanup.

If startup is quarantined after repair, set a unique one-time token in
`AUDIT_QUARANTINE_RECOVERY_TOKEN` for one process start. The token hash and
outcome are persisted beside the marker and cannot be reused. Remove the
variable after the attempt; a failed attempt remains quarantined.

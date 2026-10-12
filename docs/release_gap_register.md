# Release-gap register

This register records the remaining release and evidence gaps after the PR #7
merge. It is an audit/disposition document, not a claim that the listed
controls are implemented.

| Area | Evidence currently available | Status and gate | Smallest next action |
|---|---|---|---|
| Submission attestation requirements (ATT-01--ATT-05) | `ATTESTATION.md` binds the PR source and merged revision, includes the declaration, claim matrix, limitations, and a reproducible archive digest. | **Evidence complete; final submission review remains.** | Review the typed sign-off, submission scope, and selected artifact before submission. |
| Shared/global rate limiting and request limits (SEC-06) | `app/rate_limit.py`, request-size middleware, and endpoint tests prove process-local limiting and a 256 KiB body boundary. | **Supported prototype contract: one process/one replica.** Aggregate enforcement is not provided for multi-instance deployment. | Verify the documented process/replica contract at deployment; choose and operate a shared limiter only if multi-instance operation becomes required. |
| Credential expiry, revocation, and rotation (SEC-02) | `app/credential_store.py`, `app/security.py`, and credential lifecycle tests cover manifest states and fail-closed authority errors. | **Implemented; deployment evidence incomplete.** Filesystem ownership, rotation custody, and multi-instance operational behavior are not proven here. | Document/prove production authority permissions and run independent-instance rotation/revocation tests. |
| Signing-key custody, rollover, backup, compromise response (SEC-07) | Signing and verification code plus startup configuration checks are tested. | **Deployment-dependent.** The repository does not provide KMS/HSM custody, rollover automation, or compromise response. | Define key custody, rotation, backup, revocation, and incident procedures; add operational evidence. |
| TLS and deployment boundary (SEC-09) | Application documents trusted-proxy assumptions; no production proxy or TLS deployment is in this repository. | **Deployment-dependent mandatory evidence.** | Verify TLS termination, forwarded-header policy, network ACLs, and production configuration in the target environment. |
| Dependency vulnerability scanning and SBOM (SEC-09) | Dependencies are pinned/declared and CI installs them for tests. | **Evidence gap.** A complete vulnerability scan/SBOM is not configured or recorded. | Run a reviewed scanner and retain the report/SBOM for the release revision. |
| Sensitive logging and security-event observability (SEC-08) | Authentication errors are sanitized and security tests cover secret non-disclosure. | **Implemented locally; operational evidence incomplete.** Centralized redaction, retention, alerting, and injection controls depend on deployment. | Review sink configuration and add log-injection/observability acceptance tests. |
| PostgreSQL integration CI and skipped tests (TEST-06/TEST-08) | PR #7 workflow and PostgreSQL job succeeded for source `76e9321`, merged as `d21195c`; local required mode recorded 22 passed/0 skipped. | **Implemented and evidenced, with count limitation.** Detailed PR #7 job counts were not independently retrievable. | Preserve the job artifact/JUnit report or retrieve detailed logs for exact counts. |
| SQLite warnings and reproducible artifacts | Local suite recorded one Starlette/httpx warning; archive digest for merged `HEAD` is reproducible. | **Lower-priority quality gap.** Warning is non-failing and fixture cleanup has not been fully eliminated. | Upgrade/align the test client and close resource warnings; retain test and archive artifacts. |
| Documentation freshness (REQ-03/QUAL-04) | README, architecture, matrix, audit review, manual guide, summary, endpoint inventory, threat model, and `AI_LOG.md` were reconciled. | **Implemented for current evidence.** Historical entries remain historical. | Re-run consistency checks after any subsequent code or CI revision. |
| Backup, restore, and operational recovery | Transaction/recovery tests cover application failure paths and PostgreSQL rollback. | **Deployment-dependent.** Backup protection, restore drills, multi-host recovery, and external checkpointing are absent. | Run a protected restore drill and define independent checkpoint/retention policy if truncation detection is required. |

## Accepted or explicitly deferred scope

- No external identity provider is included; configured API-key principals remain
  the authentication model.
- No external immutable checkpoint or cloud/blockchain trust anchor is
  implemented. A valid signed-prefix tail truncation cannot be independently
  detected without a trusted retained checkpoint.
- The project-specific Python JSON representation is retained for historical
  compatibility and is not RFC 8785/JCS.
- Distributed-rate-limit implementation is deferred pending an explicit deployment decision.


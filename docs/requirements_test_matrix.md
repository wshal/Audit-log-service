# Requirements-to-test matrix

This matrix is maintained with the test suite. The default suite runs against
isolated SQLite databases, while the separately selectable PostgreSQL
integration suite lives under `tests/postgres`. Gate 3 recorded a successful
PostgreSQL CI workflow and `postgres-integration` job; detailed CI test counts
were not independently available in this review.

| ID | Requirement | Evidence | Status |
|---|---|---|---|
| AUTH-01 | Tenant and resource isolation, including direct selectors | `tests/test_tenant_authorization.py::test_two_tenant_resource_scope_and_direct_identifier_denial`, `test_same_tenant_but_ungranted_resource_and_export_are_denied`, `test_tenant_query_counts_and_pagination_do_not_disclose_foreign_rows` | Tested and verified |
| AUTH-02 | Authenticated actor binding and explicit proxy delegation | `tests/test_tenant_authorization.py::test_authenticated_actor_binding_cannot_be_replaced_by_request_actor`, `test_repository_rejects_forged_actor_without_proxy_and_preserves_database`, `test_repository_accepts_authenticated_and_explicit_proxy_attribution`, `tests/test_security_controls.py::test_writer_cannot_impersonate_another_actor` | Tested and verified |
| AUTH-03 | V1 legacy read, write, and legacy-PII capability separation | `tests/test_tenant_authorization.py::test_legacy_read_operations_require_global_auditor_and_mutations_are_denied`, `test_repository_v1_append_requires_explicit_legacy_write`, `test_legacy_pii_requires_dedicated_capability_for_compliance_and_export` | Tested and verified |
| AUTH-04 | V1/V2 integrity and transition tamper detection | `tests/test_tenant_authorization.py::test_v2_tenant_binding_and_transition_tampering_are_detected`, `test_each_v2_integrity_field_tampering_fails`, `tests/test_phase1b_migration.py::test_existing_v1_schema_migration_is_additive_and_idempotent`, `tests/test_integrity_regressions.py` | Tested and verified |
| AUTH-05 | Export and compliance scope, PII minimization, and lifecycle-manifest filtering | `tests/test_tenant_authorization.py::test_authorized_export_compliance_redaction_and_retention_are_scoped`, `test_export_lifecycle_manifests_are_database_scoped_by_tenant`, `test_compliance_unknown_or_foreign_selector_and_pii_are_denied`, `tests/test_security_controls.py::test_export_includes_lifecycle_witnesses` | Tested and verified |
| AUTH-06 | Redaction and retention authorization with non-mutation on denial | `tests/test_tenant_authorization.py::test_redaction_denial_is_indistinguishable_and_preserves_rows_and_manifests`, `test_direct_denials_preserve_retention_and_export_state`, `test_foreign_redaction_retention_and_compliance_do_not_mutate_or_leak` | Tested and verified |
| AUTH-07 | Quarantine blocks reads and mutations; readiness remains unavailable | `tests/test_preflight_quarantine.py::test_direct_entry_points_fail_closed_while_quarantined`, `test_preflight_directory_fsync_failure_retains_quarantine_and_blocks_ready`, `test_marker_removal_failure_keeps_service_quarantined` | Tested and verified |
| AUTH-08 | Recovery persistence, single-use reservation, restart, and failure handling | `tests/test_preflight_quarantine.py::test_recovery_token_concurrent_consumption_is_single_use`, `test_recovery_token_single_use_across_processes`, `test_restart_after_interruption_before_outcome_cannot_reuse_token`, `test_restart_after_outcome_before_marker_removal_cannot_reuse_token`, parametrized outcome-persistence failures | Tested and verified within the documented filesystem boundary |
| CFG-01 | Malformed authentication and resource-registry configuration fails closed | `tests/test_security_controls.py::test_malformed_api_key_configuration_fails_closed`, `test_malformed_resource_registry_fails_closed` | Tested and verified |
| DB-01 | PostgreSQL migration, constraints, allocator concurrency, and rollback | `tests/postgres/test_migrations.py`, `tests/postgres/test_concurrency.py`; [Gate 3 workflow](https://github.com/wshal/Audit-log-service/actions/runs/38090070659) and [postgres-integration job](https://github.com/wshal/Audit-log-service/actions/runs/38090070659/job/114324520174) | Executed in the recorded CI job; exact CI counts were not independently confirmed |

Latest local default validation is **142 passed, 7 skipped**. All seven local
skips are PostgreSQL database-backed cases because PostgreSQL/Docker was not
available locally. The recorded CI run provides real PostgreSQL execution
evidence; local SQLite results and CI results are intentionally reported
separately.

Coverage is measured with `pytest-cov` using line and branch instrumentation. The
85% combined gate is intentionally below the measured baseline to leave room for
platform-dependent startup and error branches while preventing material
regression. Branch coverage is reported and reviewed separately; it is not
claimed as PostgreSQL or distributed-system evidence.

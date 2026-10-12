# Requirements-to-test matrix

This matrix is maintained with the test suite. The default suite runs against
isolated SQLite databases, while the separately selectable PostgreSQL
integration suite lives under `tests/postgres`. Gate 3 and PR #5 recorded
successful PostgreSQL CI workflows. PR #5 tested source commit `23c0658`,
whose application tree was merged as `4b20228`; detailed CI test counts were
not independently available.

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
| AUTH-09 | Startup validates signing configuration before readiness; invalid production signing configuration quarantines the service | `tests/test_preflight_quarantine.py::test_production_missing_signing_key_quarantines_empty_ledger`, `test_production_invalid_public_key_ring_quarantines_empty_ledger`, `test_production_active_private_key_must_match_configured_public_key`, `test_production_malformed_private_key_quarantines_without_disclosing_value`, `test_valid_production_signing_configuration_is_ready_and_signs` | Tested and verified on the accepted working tree |
| CFG-01 | Malformed authentication and resource-registry configuration fails closed | `tests/test_security_controls.py::test_malformed_api_key_configuration_fails_closed`, `test_malformed_resource_registry_fails_closed` | Tested and verified |
| DB-01 | PostgreSQL migration, constraints, allocator concurrency, and rollback | `tests/postgres/test_migrations.py`, `tests/postgres/test_concurrency.py`; [PR #5 workflow](https://github.com/wshal/Audit-log-service/actions/runs/38173087249) and [postgres-integration job](https://github.com/wshal/Audit-log-service/actions/runs/38173087249/job/114569645659) for source `23c0658` (merged as `4b20228`) | Executed in the recorded CI job; exact CI counts were not independently confirmed |
| CHK-01 | Versioned checkpoint schema, deterministic signed bytes, separate key verification, and explicit prefix outcomes | `tests/test_checkpoints.py::test_checkpoint_serialization_is_deterministic_and_excludes_signature`, `test_checkpoint_signature_uses_separate_trusted_key_ring`, `test_checkpoint_verifier_distinguishes_identity_signature_and_hash_failures` | Tested on the current uncommitted working tree; no final-commit CI evidence |
| CHK-02 | Local ledger integrity is verified before checkpoint success; invalid chain, signatures, state, transitions, and suffixes fail closed | `tests/test_checkpoints.py::test_checkpoint_rejects_tampered_earlier_signature`, `test_checkpoint_rejects_broken_chain_and_missing_state`, `test_checkpoint_rejects_invalid_v1_v2_transition_evidence`, `test_invalid_suffix_does_not_look_like_unanchored_suffix` | Tested on the current uncommitted working tree; external checkpoint storage remains unimplemented |

Latest current working-tree validation is **208 passed, 12 skipped**. The
twelve local skips are PostgreSQL-backed cases not selected without PostgreSQL
connection configuration. The separate required-mode PostgreSQL 16 execution
completed **18 passed, zero skipped** against `audit_test`; it is not added to
the default-suite total. The recorded CI run provides additional PostgreSQL
execution evidence; local SQLite/default, local PostgreSQL, and CI results are
intentionally reported separately.

Coverage is measured with `pytest-cov` using line and branch instrumentation. The
85% combined gate is intentionally below the measured baseline to leave room for
platform-dependent startup and error branches while preventing material
regression. Branch coverage is reported and reviewed separately; it is not
claimed as PostgreSQL or distributed-system evidence.

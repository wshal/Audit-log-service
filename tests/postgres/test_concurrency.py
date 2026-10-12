import base64
import multiprocessing
import os
import time
import traceback
from multiprocessing.connection import wait as wait_for_connections

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
import pytest
from sqlalchemy import event
from sqlalchemy.orm import sessionmaker

from app.models.schemas import AuditEventCreate
from app.runtime_state import preflight_scope, set_state
from app.security import Principal
from app.services.lifecycle import LifecycleAndExportService
from app.storage.database import AuditRecordEntity, LedgerStateEntity, initialize_ledger_state, run_migrations
from app.storage.database import AuditEpochTransitionEntity
from app.storage.repository import AuditLedgerRepository
from app.services.verifier import ChainVerificationService


def _append_in_process(database_url: str, index: int) -> int:
    """Append through an independently created engine/session in a child process."""
    from sqlalchemy import create_engine

    engine = create_engine(database_url, pool_pre_ping=True)
    session = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    try:
        # Child processes do not inherit the application's in-memory readiness
        # state. The parent has already migrated and initialized this empty,
        # verified test ledger; establish that direct-service precondition here.
        set_state("healthy")
        event = AuditEventCreate(
            eventType="POSTGRES_CONCURRENT_WRITE",
            actorId=f"process-{index}",
            resourceType="TEST",
            resourceId=f"resource-{index}",
            payload={"index": index},
            timestamp=f"2026-10-07T00:00:{index:02d}Z",
        )
        principal = Principal(
            f"process-{index}",
            frozenset({"writer"}),
            "postgres-concurrency",
            (),
            False,
            True,
        )
        return AuditLedgerRepository(session).append_event(event, principal).sequence_num
    finally:
        session.close()
        engine.dispose()


def _append_process_entry(database_url: str, index: int, result_connection) -> None:
    try:
        result = ("ok", index, _append_in_process(database_url, index))
    except BaseException:
        result = ("error", index, traceback.format_exc())
    result_connection.send(result)
    result_connection.close()


def _collect_worker_results(processes, connections, deadline):
    """Collect one result per spawned worker through bounded pipe reads."""
    pending = {connection: index for index, connection in enumerate(connections)}
    results = {}
    while pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            missing = sorted(pending.values())
            raise TimeoutError(f"Timed out waiting for worker results: {missing}")
        ready = wait_for_connections(list(pending), timeout=min(remaining, 0.5))
        if not ready:
            if all(not process.is_alive() for process in processes):
                missing = sorted(pending.values())
                exit_codes = [process.exitcode for process in processes]
                raise RuntimeError(
                    f"Workers exited without results; missing={missing}, exit_codes={exit_codes}"
                )
            continue
        for connection in ready:
            index = pending.pop(connection)
            try:
                status, result_index, value = connection.recv()
            except EOFError as exc:
                raise RuntimeError(
                    f"Worker {index} exited before sending a result "
                    f"(exit code {processes[index].exitcode})"
                ) from exc
            if result_index != index:
                raise RuntimeError(
                    f"Worker result identity mismatch: expected {index}, got {result_index}"
                )
            if status == "error":
                raise RuntimeError(f"PostgreSQL append worker {index} failed: {value}")
            if status != "ok":
                raise RuntimeError(f"Worker {index} returned unknown status {status!r}")
            results[index] = value
    return results


def _assert_worker_exit_codes(started):
    abnormal = [(index, process.exitcode) for index, process in started if process.exitcode != 0]
    if abnormal:
        details = ", ".join(f"worker {index}: exit code {code}" for index, code in abnormal)
        raise RuntimeError(f"PostgreSQL append workers exited abnormally: {details}")


def _transport_test_worker(result_connection, index, mode):
    if mode == "ok":
        result_connection.send(("ok", index, 42))
    elif mode == "error":
        result_connection.send(("error", index, "synthetic worker traceback"))
    elif mode == "eof":
        result_connection.close()
        return
    elif mode == "timeout":
        time.sleep(2)
        return
    elif mode == "nonzero":
        result_connection.send(("ok", index, 42))
        os._exit(7)
    result_connection.close()


def _snapshot_ledger(session):
    records = session.query(AuditRecordEntity).order_by(AuditRecordEntity.sequence_num.asc()).all()
    transitions = session.query(AuditEpochTransitionEntity).order_by(AuditEpochTransitionEntity.id.asc()).all()
    state = session.query(LedgerStateEntity).filter_by(singleton_id=1).one_or_none()
    record_fields = (
        "id", "sequence_num", "event_type", "actor_id", "resource_type", "resource_id",
        "payload_json", "timestamp", "content_hash", "prev_hash", "record_hash",
        "record_signature", "signing_key_id", "is_archived", "archived_at",
        "archival_reason", "redaction_metadata_json", "tenant_id", "authenticated_subject",
        "credential_id", "attribution_mode", "delegation_reason", "protocol_version",
    )
    transition_fields = (
        "id", "legacy_tip_hash", "legacy_record_count", "v2_genesis_hash",
        "v2_genesis_sequence", "cutover_timestamp", "transition_hash",
        "transition_signature", "signing_key_id", "protocol_version",
    )
    return {
        "records": [tuple(getattr(record, field) for field in record_fields) for record in records],
        "transitions": [tuple(getattr(transition, field) for field in transition_fields) for transition in transitions],
        "state": None if state is None else (
            state.singleton_id, state.next_sequence, state.tip_hash, state.state_version
        ),
    }


def _postgres_writer() -> Principal:
    return Principal("writer", frozenset({"writer"}), "postgres-tests", (), False, True)


def _event(index: int) -> AuditEventCreate:
    return AuditEventCreate(
        eventType="POSTGRES_APPEND",
        actorId="writer",
        resourceType="TEST",
        resourceId=f"resource-{index}",
        payload={"index": index},
        timestamp=f"2026-10-07T01:00:{index:02d}Z",
    )


def _provision_test_signing_key(monkeypatch):
    key = Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    monkeypatch.setenv("AUDIT_SIGNING_PRIVATE_KEY", base64.b64encode(key).decode("ascii"))


def test_postgres_independent_processes_serialize_append_and_preserve_chain(postgres_engine, monkeypatch):
    _provision_test_signing_key(monkeypatch)
    run_migrations(postgres_engine)
    initialize_ledger_state(postgres_engine)
    database_url = os.environ["POSTGRES_TEST_DATABASE_URL"]

    context = multiprocessing.get_context("spawn")
    workers = []
    started = []
    deadline = time.monotonic() + 30
    failure = None
    try:
        for index in range(16):
            parent_connection, child_connection = context.Pipe(duplex=False)
            process = context.Process(
                target=_append_process_entry,
                args=(database_url, index, child_connection),
            )
            try:
                process.start()
            except BaseException:
                parent_connection.close()
                raise
            finally:
                # The child owns this endpoint after spawn; retaining it in the
                # parent would prevent EOF from being observable on failure.
                child_connection.close()
            workers.append((index, process, parent_connection))
            started.append((index, process))

        processes = [process for _, process, _ in workers]
        connections = [connection for _, _, connection in workers]
        results = _collect_worker_results(processes, connections, deadline)
        sequence_numbers = [results[index] for index in range(len(processes))]
    except BaseException as exc:
        # Preserve the first worker/timeout failure. Cleanup must not replace
        # its useful traceback with synthetic termination exit codes.
        failure = (exc, exc.__traceback__)
    finally:
        # Give workers a bounded opportunity to finish naturally. If the
        # operation failed, terminate remaining workers so cleanup is bounded.
        cleanup_deadline = time.monotonic() + 5
        for _, process in started:
            remaining = cleanup_deadline - time.monotonic()
            if remaining > 0:
                process.join(timeout=remaining)
        if failure is not None:
            for _, process in started:
                if process.is_alive():
                    process.terminate()
            terminate_deadline = time.monotonic() + 5
            for _, process in started:
                remaining = terminate_deadline - time.monotonic()
                if remaining > 0 and process.is_alive():
                    process.join(timeout=remaining)
        for _, process in started:
            if process.is_alive():
                process.kill()
                process.join(timeout=1)
        for _, _, connection in workers:
            connection.close()

    if failure is not None:
        raise failure[0].with_traceback(failure[1])

    _assert_worker_exit_codes(started)

    Session = sessionmaker(autocommit=False, autoflush=False, bind=postgres_engine)
    session = Session()
    try:
        records = session.query(AuditRecordEntity).order_by(AuditRecordEntity.sequence_num.asc()).all()
        state = session.query(LedgerStateEntity).filter_by(singleton_id=1).one()
        assert sorted(sequence_numbers) == list(range(1, 17))
        assert [record.sequence_num for record in records] == list(range(1, 17))
        assert len({record.sequence_num for record in records}) == 16
        assert state.next_sequence == 17
        assert state.tip_hash == records[-1].record_hash
        assert all(current.prev_hash == previous.record_hash for previous, current in zip(records, records[1:]))
        with preflight_scope():
            verification = ChainVerificationService.verify_ledger(
                session,
                principal=Principal("global-auditor", frozenset({"global_auditor"}), "postgres-verifier"),
            )
        assert verification.intact is True
    finally:
        session.close()


def test_worker_transport_propagates_explicit_error():
    context = multiprocessing.get_context("spawn")
    parent_connection, child_connection = context.Pipe(duplex=False)
    process = context.Process(target=_transport_test_worker, args=(child_connection, 0, "error"))
    process.start()
    child_connection.close()
    try:
        with pytest.raises(RuntimeError, match="synthetic worker traceback"):
            _collect_worker_results([process], [parent_connection], time.monotonic() + 5)
        process.join(timeout=5)
        _assert_worker_exit_codes([(0, process)])
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=1)
        parent_connection.close()


def test_worker_transport_detects_eof_before_result():
    context = multiprocessing.get_context("spawn")
    parent_connection, child_connection = context.Pipe(duplex=False)
    process = context.Process(target=_transport_test_worker, args=(child_connection, 0, "eof"))
    process.start()
    child_connection.close()
    try:
        with pytest.raises(RuntimeError, match="exited before sending"):
            _collect_worker_results([process], [parent_connection], time.monotonic() + 5)
        process.join(timeout=5)
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=1)
        parent_connection.close()


def test_worker_transport_timeout_is_bounded():
    context = multiprocessing.get_context("spawn")
    parent_connection, child_connection = context.Pipe(duplex=False)
    process = context.Process(target=_transport_test_worker, args=(child_connection, 0, "timeout"))
    process.start()
    child_connection.close()
    try:
        with pytest.raises(TimeoutError, match="Timed out waiting"):
            _collect_worker_results([process], [parent_connection], time.monotonic() + 0.1)
    finally:
        if process.is_alive():
            process.kill()
        process.join(timeout=2)
        parent_connection.close()


def test_worker_transport_checks_nonzero_exit_after_success():
    context = multiprocessing.get_context("spawn")
    parent_connection, child_connection = context.Pipe(duplex=False)
    process = context.Process(target=_transport_test_worker, args=(child_connection, 0, "nonzero"))
    process.start()
    child_connection.close()
    try:
        assert _collect_worker_results([process], [parent_connection], time.monotonic() + 5) == {0: 42}
        process.join(timeout=5)
        with pytest.raises(RuntimeError, match=r"worker 0: exit code 7"):
            _assert_worker_exit_codes([(0, process)])
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=1)
        parent_connection.close()


def test_postgres_append_failure_rolls_back_and_session_remains_usable(postgres_engine, monkeypatch):
    _provision_test_signing_key(monkeypatch)
    run_migrations(postgres_engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=postgres_engine)
    session = Session()
    failed = {"value": False}

    def fail_once(current_session, flush_context, instances):
        if not failed["value"]:
            failed["value"] = True
            raise RuntimeError("injected PostgreSQL flush failure")

    event.listen(session, "before_flush", fail_once)
    try:
        try:
            AuditLedgerRepository(session).append_event(_event(1), _postgres_writer())
        except RuntimeError as exc:
            assert str(exc) == "injected PostgreSQL flush failure"
        else:
            raise AssertionError("the injected flush failure was not raised")
    finally:
        event.remove(session, "before_flush", fail_once)

    assert session.query(AuditRecordEntity).count() == 0
    state = session.query(LedgerStateEntity).filter_by(singleton_id=1).one_or_none()
    assert state is None
    session.rollback()

    record = AuditLedgerRepository(session).append_event(_event(2), _postgres_writer())
    assert record.sequence_num == 1
    session.close()


def test_postgres_lifecycle_failure_rolls_back_record_and_ledger_state(postgres_engine, monkeypatch):
    _provision_test_signing_key(monkeypatch)
    run_migrations(postgres_engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=postgres_engine)
    append_session = Session()
    try:
        AuditLedgerRepository(append_session).append_event(_event(1), _postgres_writer())
    finally:
        append_session.close()

    before_snapshot_session = Session()
    try:
        before_snapshot = _snapshot_ledger(before_snapshot_session)
    finally:
        before_snapshot_session.close()

    lifecycle_session = Session()
    original = LifecycleAndExportService._append_lifecycle_journal

    def fail_journal(*args, **kwargs):
        raise RuntimeError("injected lifecycle journal failure")

    monkeypatch.setattr(LifecycleAndExportService, "_append_lifecycle_journal", staticmethod(fail_journal))
    try:
        try:
            LifecycleAndExportService.apply_retention_policy(
                lifecycle_session,
                retention_days=1,
                reason="test failure",
                principal=Principal(
                    "auditor",
                    frozenset({"retention_admin", "global_auditor"}),
                    "postgres-lifecycle",
                ),
            )
        except RuntimeError as exc:
            assert str(exc) == "injected lifecycle journal failure"
        else:
            raise AssertionError("the injected lifecycle failure was not raised")
    finally:
        monkeypatch.setattr(LifecycleAndExportService, "_append_lifecycle_journal", staticmethod(original))

    after_snapshot_session = Session()
    try:
        after_snapshot = _snapshot_ledger(after_snapshot_session)
    finally:
        after_snapshot_session.close()
    assert after_snapshot == before_snapshot
    lifecycle_session.rollback()

    # The same session can perform a subsequent valid lifecycle operation.
    result = LifecycleAndExportService.apply_retention_policy(
        lifecycle_session,
        retention_days=1,
        reason="test retry after rollback",
        principal=Principal(
            "auditor",
            frozenset({"retention_admin", "global_auditor"}),
            "postgres-lifecycle",
        ),
    )
    assert result.recordsArchived == 1
    lifecycle_session.close()

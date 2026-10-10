"""Migration and legacy-epoch safety checks for Phase 1B."""

from sqlalchemy import create_engine, inspect, text

from app.storage.database import init_db


def test_existing_v1_schema_migration_is_additive_and_idempotent(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}")
    with engine.begin() as connection:
        connection.execute(text("""
            CREATE TABLE audit_records (
              id INTEGER PRIMARY KEY, sequence_num INTEGER NOT NULL UNIQUE,
              event_type VARCHAR(128) NOT NULL, actor_id VARCHAR(128) NOT NULL,
              resource_type VARCHAR(128) NOT NULL, resource_id VARCHAR(256) NOT NULL,
              payload_json TEXT NOT NULL, timestamp VARCHAR(64) NOT NULL,
              content_hash VARCHAR(64) NOT NULL, prev_hash VARCHAR(64) NOT NULL,
              record_hash VARCHAR(64) NOT NULL, is_archived BOOLEAN NOT NULL DEFAULT 0,
              archived_at VARCHAR(64), archival_reason VARCHAR(256),
              redaction_metadata_json TEXT
            )
        """))
        connection.execute(text("INSERT INTO audit_records VALUES (1,1,'V1','actor','CLIENT','c','{}','2026-01-01T00:00:00Z','c','p','r',0,NULL,NULL,NULL)"))
    init_db(engine)
    original = engine.connect().execute(text("SELECT payload_json, content_hash, prev_hash, record_hash FROM audit_records WHERE id=1")).one()
    init_db(engine)
    current = engine.connect().execute(text("SELECT payload_json, content_hash, prev_hash, record_hash FROM audit_records WHERE id=1")).one()
    assert tuple(original) == tuple(current)
    columns = {column["name"] for column in inspect(engine).get_columns("audit_records")}
    assert {"tenant_id", "protocol_version", "authenticated_subject"}.issubset(columns)


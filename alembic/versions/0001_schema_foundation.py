"""Establish the versioned schema and ledger-state foundation."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "0001_schema_foundation"
down_revision = None
branch_labels = None
depends_on = None


BASE_AUDIT_COLUMNS = {
    "id", "sequence_num", "event_type", "actor_id", "resource_type", "resource_id",
    "payload_json", "timestamp", "content_hash", "prev_hash", "record_hash",
    "is_archived", "archived_at", "archival_reason", "redaction_metadata_json",
}


def _add_legacy_columns(bind) -> None:
    columns = {column["name"] for column in inspect(bind).get_columns("audit_records")}
    additions = {
        "record_signature": sa.Text(),
        "signing_key_id": sa.String(128),
        "tenant_id": sa.String(128),
        "authenticated_subject": sa.String(128),
        "credential_id": sa.String(128),
        "attribution_mode": sa.String(32),
        "delegation_reason": sa.String(512),
        "protocol_version": sa.Integer(),
    }
    for name, column_type in additions.items():
        if name not in columns:
            op.add_column(
                "audit_records",
                sa.Column(
                    name,
                    column_type,
                    nullable=name != "protocol_version",
                    server_default="1" if name == "protocol_version" else None,
                ),
            )


def _add_transition_columns(bind) -> None:
    if "audit_epoch_transitions" not in inspect(bind).get_table_names():
        return
    columns = {column["name"] for column in inspect(bind).get_columns("audit_epoch_transitions")}
    additions = {
        "v2_genesis_sequence": sa.Integer(),
        "cutover_timestamp": sa.String(64),
    }
    for name, column_type in additions.items():
        if name not in columns:
            op.add_column(
                "audit_epoch_transitions",
                sa.Column(name, column_type, nullable=False, server_default="0" if name == "v2_genesis_sequence" else ""),
            )


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())

    if "audit_records" not in tables:
        # The versioned baseline is the only fresh-install bootstrap. Future
        # upgrades must use revisions and never rely on create_all().
        from app.storage.database import Base
        Base.metadata.create_all(bind=bind)
        return

    from app.storage.database import validate_pre_migration_schema
    validate_pre_migration_schema(bind)

    _add_legacy_columns(bind)
    _add_transition_columns(bind)
    # Create only missing current tables; never rewrite or remove existing rows.
    from app.storage.database import Base
    Base.metadata.create_all(
        bind=bind,
        tables=[
            Base.metadata.tables["audit_epoch_transitions"],
            Base.metadata.tables["ledger_state"],
        ],
    )


def downgrade() -> None:
    # Historical data must not be destructively downgraded automatically.
    raise RuntimeError("The audit schema foundation has no automatic destructive downgrade")

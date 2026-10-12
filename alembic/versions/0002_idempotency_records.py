"""Add durable idempotency results for keyed audit-event retries."""

from alembic import op
import sqlalchemy as sa


revision = "0002_idempotency_records"
down_revision = "0001_schema_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "idempotency_records" in inspector.get_table_names():
        return
    op.create_table(
        "idempotency_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scope_principal", sa.String(length=256), nullable=False),
        sa.Column("scope_tenant", sa.String(length=128), nullable=False),
        sa.Column("scope_method", sa.String(length=16), nullable=False),
        sa.Column("scope_endpoint", sa.String(length=128), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("audit_record_id", sa.Integer(), sa.ForeignKey("audit_records.id"), nullable=False),
        sa.Column("created_at", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.String(length=64), nullable=False),
        sa.UniqueConstraint(
            "scope_principal", "scope_tenant", "scope_method",
            "scope_endpoint", "idempotency_key",
            name="uq_idempotency_scope_key",
        ),
    )


def downgrade() -> None:
    # Idempotency evidence is part of the append safety boundary.  A routine
    # downgrade must never silently delete it and reopen duplicate appends.
    raise RuntimeError("The idempotency schema has no automatic destructive downgrade")

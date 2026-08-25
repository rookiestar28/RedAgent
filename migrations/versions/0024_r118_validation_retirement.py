"""Retire the unconsumed compat_118 campaign-controller schema."""

from alembic import op
import sqlalchemy as sa


revision = "0024_r118_retirement"
down_revision = "0023_r118_controller"
branch_labels = None
depends_on = None

TABLE = "r118_campaign_controller_records"
ARTIFACT_TABLE = "r118_campaign_controller_artifacts"


def upgrade() -> None:
    # IMPORTANT: preserve 0023 as migration history; only the current active
    # schema is retired so databases already at that revision can advance.
    op.drop_table(ARTIFACT_TABLE)
    op.drop_table(TABLE)


def downgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("campaign_id", sa.String(100), primary_key=True),
        sa.Column("record_sha256", sa.String(64), nullable=False),
        sa.Column("record_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("controller_epoch", sa.Integer(), nullable=False),
        sa.Column("state_version", sa.BigInteger(), nullable=False),
        sa.Column("campaign_state", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "record_sha256 ~ '^[0-9a-f]{64}$'",
            name="record_sha256_hex",
        ),
        sa.CheckConstraint(
            "octet_length(record_bytes) BETWEEN 1 AND 8388608",
            name="record_bytes_bounded",
        ),
        sa.CheckConstraint(
            "controller_epoch BETWEEN 1 AND 999999999",
            name="controller_epoch_positive",
        ),
        sa.CheckConstraint(
            "state_version BETWEEN 1 AND 9223372036854775807",
            name="state_version_positive",
        ),
        sa.CheckConstraint(
            "campaign_state IN ('APPROVED','ACTIVE','CLAIMED','PAUSED','COMPLETED','REVOKED','EXPIRED')",
            name="campaign_state_closed",
        ),
    )
    op.execute(f'ALTER TABLE "{TABLE}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{TABLE}" FORCE ROW LEVEL SECURITY')
    op.execute(
        f'CREATE POLICY "{TABLE}_service_isolation" ON "{TABLE}" '
        "USING (current_user = NULLIF(current_setting('redagent.campaign_controller_role', true), '')) "
        "WITH CHECK (current_user = NULLIF(current_setting('redagent.campaign_controller_role', true), ''))"
    )
    op.execute(f'REVOKE ALL ON TABLE "{TABLE}" FROM PUBLIC')

    op.create_table(
        ARTIFACT_TABLE,
        sa.Column(
            "campaign_id",
            sa.String(100),
            sa.ForeignKey(f"{TABLE}.campaign_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("artifact_sha256", sa.String(64), primary_key=True),
        sa.Column("artifact_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "artifact_sha256 ~ '^[0-9a-f]{64}$'",
            name="artifact_sha256_hex",
        ),
        sa.CheckConstraint(
            "octet_length(artifact_bytes) BETWEEN 1 AND 65536",
            name="artifact_bytes_bounded",
        ),
    )
    op.execute(f'ALTER TABLE "{ARTIFACT_TABLE}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{ARTIFACT_TABLE}" FORCE ROW LEVEL SECURITY')
    op.execute(
        f'CREATE POLICY "{ARTIFACT_TABLE}_service_isolation" ON "{ARTIFACT_TABLE}" '
        "USING (current_user = NULLIF(current_setting('redagent.campaign_controller_role', true), '')) "
        "WITH CHECK (current_user = NULLIF(current_setting('redagent.campaign_controller_role', true), ''))"
    )
    op.execute(f'REVOKE ALL ON TABLE "{ARTIFACT_TABLE}" FROM PUBLIC')

"""Add immutable autonomous campaign plan previews and approval receipts."""

from alembic import op
import sqlalchemy as sa


revision = "0030_autonomous_plan_approval"
down_revision = "0029_autonomous_campaign_app"
branch_labels = None
depends_on = None


_APPROVAL_TABLES = (
    "autonomous_campaign_plan_approval_receipts",
    "autonomous_campaign_plan_previews",
)
_TENANT_SECURITY_STATEMENTS = (
    "ALTER TABLE autonomous_campaign_plan_previews ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE autonomous_campaign_plan_previews FORCE ROW LEVEL SECURITY",
    "CREATE POLICY autonomous_campaign_plan_previews_tenant_isolation ON "
    "autonomous_campaign_plan_previews USING "
    "(tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK "
    "(tenant_id = current_setting('redagent.tenant_id', true))",
    "REVOKE UPDATE, DELETE ON autonomous_campaign_plan_previews FROM PUBLIC",
    "ALTER TABLE autonomous_campaign_plan_approval_receipts ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE autonomous_campaign_plan_approval_receipts FORCE ROW LEVEL SECURITY",
    "CREATE POLICY autonomous_campaign_plan_approval_receipts_tenant_isolation ON "
    "autonomous_campaign_plan_approval_receipts USING "
    "(tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK "
    "(tenant_id = current_setting('redagent.tenant_id', true))",
    "REVOKE UPDATE, DELETE ON autonomous_campaign_plan_approval_receipts FROM PUBLIC",
)


def _owned_columns() -> tuple[sa.Column, ...]:
    return (
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def upgrade() -> None:
    op.create_table(
        "autonomous_campaign_plan_previews",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("application_id", sa.String(64), nullable=False),
        sa.Column("application_revision", sa.BigInteger(), nullable=False),
        sa.Column("contract_version", sa.String(100), nullable=False),
        sa.Column("preview_sha256", sa.String(64), nullable=False),
        sa.Column("preview_payload", sa.JSON(), nullable=False),
        sa.Column("created_by_user_id", sa.String(64), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        *_owned_columns(),
        sa.ForeignKeyConstraint(
            ("tenant_id", "application_id"),
            ("autonomous_campaign_applications.tenant_id", "autonomous_campaign_applications.id"),
            name="fk_autonomous_campaign_plan_preview_tenant_application",
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_autonomous_campaign_plan_preview_tenant_identity"),
        sa.UniqueConstraint(
            "tenant_id",
            "application_id",
            "application_revision",
            name="uq_autonomous_campaign_plan_preview_revision",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "application_id",
            "preview_sha256",
            name="uq_autonomous_campaign_plan_preview_digest",
        ),
        sa.CheckConstraint(
            "contract_version = 'redagent.autonomous-campaign-plan-preview/v1'",
            name="autonomous_campaign_plan_preview_contract_version_closed",
        ),
        sa.CheckConstraint(
            "application_revision BETWEEN 1 AND 2147483647",
            name="autonomous_campaign_plan_preview_revision_bounded",
        ),
    )
    op.create_table(
        "autonomous_campaign_plan_approval_receipts",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("application_id", sa.String(64), nullable=False),
        sa.Column("preview_id", sa.String(64), nullable=False),
        sa.Column("application_revision", sa.BigInteger(), nullable=False),
        sa.Column("contract_version", sa.String(100), nullable=False),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("reason_code", sa.String(150), nullable=False),
        sa.Column("receipt_sha256", sa.String(64), nullable=False),
        sa.Column("receipt_payload", sa.JSON(), nullable=False),
        sa.Column("decided_by_user_id", sa.String(64), sa.ForeignKey("users.id"), nullable=False),
        *_owned_columns(),
        sa.ForeignKeyConstraint(
            ("tenant_id", "application_id"),
            ("autonomous_campaign_applications.tenant_id", "autonomous_campaign_applications.id"),
            name="fk_autonomous_campaign_approval_tenant_application",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "preview_id"),
            ("autonomous_campaign_plan_previews.tenant_id", "autonomous_campaign_plan_previews.id"),
            name="fk_autonomous_campaign_approval_tenant_preview",
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_autonomous_campaign_approval_tenant_identity"),
        sa.UniqueConstraint(
            "tenant_id",
            "application_id",
            "application_revision",
            name="uq_autonomous_campaign_approval_revision",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "application_id",
            "receipt_sha256",
            name="uq_autonomous_campaign_approval_digest",
        ),
        sa.CheckConstraint(
            "contract_version = 'redagent.autonomous-campaign-plan-approval-receipt/v1'",
            name="autonomous_campaign_approval_contract_version_closed",
        ),
        sa.CheckConstraint("decision IN ('approved','denied')", name="autonomous_campaign_approval_decision_closed"),
        sa.CheckConstraint(
            "application_revision BETWEEN 1 AND 2147483647",
            name="autonomous_campaign_approval_revision_bounded",
        ),
    )

    for statement in _TENANT_SECURITY_STATEMENTS:
        op.execute(statement)

    # CRITICAL: previews and decisions are approval evidence; coherent rewrites must be impossible.
    op.execute(
        "CREATE FUNCTION redagent_reject_autonomous_campaign_plan_preview_mutation() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION "
        "'autonomous_campaign_plan_preview_immutable'; END $$"
    )
    op.execute(
        "CREATE TRIGGER autonomous_campaign_plan_preview_immutable BEFORE UPDATE OR DELETE "
        "ON autonomous_campaign_plan_previews FOR EACH ROW EXECUTE FUNCTION "
        "redagent_reject_autonomous_campaign_plan_preview_mutation()"
    )
    op.execute(
        "CREATE FUNCTION redagent_reject_autonomous_campaign_plan_approval_receipt_mutation() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION "
        "'autonomous_campaign_plan_approval_receipt_immutable'; END $$"
    )
    op.execute(
        "CREATE TRIGGER autonomous_campaign_plan_approval_receipt_immutable BEFORE UPDATE OR DELETE "
        "ON autonomous_campaign_plan_approval_receipts FOR EACH ROW EXECUTE FUNCTION "
        "redagent_reject_autonomous_campaign_plan_approval_receipt_mutation()"
    )


def _has_persisted_approval_state(connection: sa.Connection) -> bool:
    relaxed_tables: list[str] = []
    try:
        for table_name in _APPROVAL_TABLES:
            # CRITICAL: FORCE RLS can hide populated approval evidence and permit destructive rollback.
            connection.execute(sa.text(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY"))
            relaxed_tables.append(table_name)
        return any(
            connection.execute(sa.text(f"SELECT 1 FROM {table_name} LIMIT 1")).first() is not None
            for table_name in _APPROVAL_TABLES
        )
    finally:
        for table_name in reversed(relaxed_tables):
            connection.execute(sa.text(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY"))


def downgrade() -> None:
    connection = op.get_bind()
    if _has_persisted_approval_state(connection):
        raise RuntimeError("autonomous_campaign_plan_approval_downgrade_requires_empty_state")
    op.execute(
        "DROP TRIGGER IF EXISTS autonomous_campaign_plan_approval_receipt_immutable "
        "ON autonomous_campaign_plan_approval_receipts"
    )
    op.execute("DROP FUNCTION IF EXISTS redagent_reject_autonomous_campaign_plan_approval_receipt_mutation()")
    op.execute(
        "DROP TRIGGER IF EXISTS autonomous_campaign_plan_preview_immutable "
        "ON autonomous_campaign_plan_previews"
    )
    op.execute("DROP FUNCTION IF EXISTS redagent_reject_autonomous_campaign_plan_preview_mutation()")
    op.drop_table("autonomous_campaign_plan_approval_receipts")
    op.drop_table("autonomous_campaign_plan_previews")

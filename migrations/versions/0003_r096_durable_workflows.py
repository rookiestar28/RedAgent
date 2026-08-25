"""Add compat_096 durable campaign, workflow, and command reconciliation state."""

from alembic import op
import sqlalchemy as sa


revision = "0003_r096_durable_workflows"
down_revision = "0002_r094_enterprise_identity"
branch_labels = None
depends_on = None


compat_096_TABLES = ("campaigns", "workflow_commands")


def _owned_columns() -> tuple[sa.Column, ...]:
    return (
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def upgrade() -> None:
    op.create_table("campaigns", sa.Column("id", sa.String(64), primary_key=True), sa.Column("engagement_id", sa.String(64), sa.ForeignKey("engagements.id"), nullable=False), sa.Column("roe_version_id", sa.String(64), sa.ForeignKey("roe_versions.id"), nullable=False), sa.Column("name", sa.String(200), nullable=False), sa.Column("status", sa.String(32), nullable=False), sa.Column("workflow_id", sa.String(64), nullable=False), sa.Column("workflow_run_id", sa.String(64)), sa.Column("orchestration_revision", sa.Integer(), nullable=False, server_default="1"), *_owned_columns(), sa.UniqueConstraint("tenant_id", "workflow_id"))
    op.create_table("workflow_commands", sa.Column("id", sa.String(64), primary_key=True), sa.Column("job_id", sa.String(64), sa.ForeignKey("jobs.id"), nullable=False), sa.Column("command_id", sa.String(64), nullable=False), sa.Column("action", sa.String(32), nullable=False), sa.Column("request_hash", sa.String(64), nullable=False), sa.Column("state", sa.String(32), nullable=False), sa.Column("result_revision", sa.Integer(), nullable=False), sa.Column("actor_user_id", sa.String(64), nullable=False), sa.Column("expected_revision", sa.Integer(), nullable=False), sa.Column("policy_reference", sa.String(100), nullable=False), sa.Column("audit_id", sa.String(64)), sa.Column("outbox_id", sa.String(64)), *_owned_columns(), sa.UniqueConstraint("tenant_id", "job_id", "command_id"))

    op.add_column("jobs", sa.Column("campaign_id", sa.String(64), nullable=True))
    op.create_foreign_key("fk_jobs_campaign_id_campaigns", "jobs", "campaigns", ["campaign_id"], ["id"])
    op.add_column("jobs", sa.Column("created_by_user_id", sa.String(64), nullable=False, server_default="migration"))
    op.alter_column("jobs", "created_by_user_id", server_default=None)
    op.add_column("jobs", sa.Column("policy_reference", sa.String(100), nullable=False, server_default="migration:legacy"))
    op.alter_column("jobs", "policy_reference", server_default=None)
    op.add_column("jobs", sa.Column("workflow_id", sa.String(64), nullable=True))
    op.add_column("jobs", sa.Column("workflow_run_id", sa.String(64), nullable=True))
    op.add_column("jobs", sa.Column("orchestration_state", sa.String(32), nullable=False, server_default="dispatch_pending"))
    op.add_column("jobs", sa.Column("orchestration_revision", sa.Integer(), nullable=False, server_default="1"))
    op.add_column("jobs", sa.Column("current_gate", sa.String(100), nullable=False, server_default="temporal_dispatch_pending"))
    op.add_column("jobs", sa.Column("failure_code", sa.String(100), nullable=True))
    op.add_column("jobs", sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("jobs", sa.Column("dispatch_blocked", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("jobs", sa.Column("stop_requested", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_unique_constraint("uq_jobs_tenant_workflow_id", "jobs", ["tenant_id", "workflow_id"])

    # CRITICAL: orchestration records remain FORCE RLS even when workers reconcile retries.
    rls_statements = (
        "ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE campaigns FORCE ROW LEVEL SECURITY",
        "CREATE POLICY campaigns_tenant_isolation ON campaigns USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK (tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE workflow_commands ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE workflow_commands FORCE ROW LEVEL SECURITY",
        "CREATE POLICY workflow_commands_tenant_isolation ON workflow_commands USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK (tenant_id = current_setting('redagent.tenant_id', true))",
    )
    for statement in rls_statements:
        op.execute(statement)


def downgrade() -> None:
    op.drop_constraint("uq_jobs_tenant_workflow_id", "jobs", type_="unique")
    for column in (
        "stop_requested",
        "dispatch_blocked",
        "retry_count",
        "failure_code",
        "current_gate",
        "orchestration_revision",
        "orchestration_state",
        "workflow_run_id",
        "workflow_id",
        "created_by_user_id",
        "policy_reference",
    ):
        op.drop_column("jobs", column)
    op.drop_constraint("fk_jobs_campaign_id_campaigns", "jobs", type_="foreignkey")
    op.drop_column("jobs", "campaign_id")
    op.drop_table("workflow_commands")
    op.drop_table("campaigns")

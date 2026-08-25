"""Create the compat_093 control-plane system of record."""

from alembic import op
import sqlalchemy as sa


revision = "0001_r093_control_plane"
down_revision = None
branch_labels = None
depends_on = None


TENANT_TABLES = (
    "users", "engagements", "targets", "roe_versions", "approvals", "policy_references",
    "jobs", "audit_events", "outbox_events", "idempotency_records", "issue_definitions", "finding_instances",
)


def _owned_columns() -> tuple[sa.Column, ...]:
    return (
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def upgrade() -> None:
    op.create_table("tenants", sa.Column("id", sa.String(64), primary_key=True), sa.Column("name", sa.String(200), nullable=False), sa.Column("version", sa.Integer(), nullable=False, server_default="1"), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("users", sa.Column("id", sa.String(64), primary_key=True), sa.Column("subject", sa.String(200), nullable=False), *_owned_columns(), sa.UniqueConstraint("tenant_id", "subject"))
    op.create_table("engagements", sa.Column("id", sa.String(64), primary_key=True), sa.Column("name", sa.String(200), nullable=False), sa.Column("owner_user_id", sa.String(64), nullable=False), *_owned_columns())
    op.create_table("targets", sa.Column("id", sa.String(64), primary_key=True), sa.Column("engagement_id", sa.String(64), sa.ForeignKey("engagements.id"), nullable=False), sa.Column("target_type", sa.String(32), nullable=False), sa.Column("normalized_value", sa.String(500), nullable=False), *_owned_columns(), sa.UniqueConstraint("tenant_id", "engagement_id", "normalized_value"))
    op.create_table("roe_versions", sa.Column("id", sa.String(64), primary_key=True), sa.Column("engagement_id", sa.String(64), sa.ForeignKey("engagements.id"), nullable=False), sa.Column("revision", sa.Integer(), nullable=False), sa.Column("status", sa.String(32), nullable=False), sa.Column("document", sa.JSON(), nullable=False), *_owned_columns(), sa.UniqueConstraint("tenant_id", "engagement_id", "revision"))
    op.create_table("approvals", sa.Column("id", sa.String(64), primary_key=True), sa.Column("roe_version_id", sa.String(64), sa.ForeignKey("roe_versions.id"), nullable=False), sa.Column("approved_by_user_id", sa.String(64), nullable=False), *_owned_columns())
    op.create_table("policy_references", sa.Column("id", sa.String(64), primary_key=True), sa.Column("roe_version_id", sa.String(64), sa.ForeignKey("roe_versions.id"), nullable=False), sa.Column("policy_name", sa.String(200), nullable=False), sa.Column("policy_version", sa.String(100), nullable=False), *_owned_columns())
    op.create_table("jobs", sa.Column("id", sa.String(64), primary_key=True), sa.Column("engagement_id", sa.String(64), sa.ForeignKey("engagements.id"), nullable=False), sa.Column("roe_version_id", sa.String(64), sa.ForeignKey("roe_versions.id"), nullable=False), sa.Column("status", sa.String(32), nullable=False), sa.Column("request", sa.JSON(), nullable=False), *_owned_columns())
    op.create_table("audit_events", sa.Column("id", sa.String(64), primary_key=True), sa.Column("actor_user_id", sa.String(64), nullable=False), sa.Column("action", sa.String(100), nullable=False), sa.Column("subject_type", sa.String(100), nullable=False), sa.Column("subject_id", sa.String(64), nullable=False), sa.Column("correlation_id", sa.String(100), nullable=False), sa.Column("details", sa.JSON(), nullable=False), *_owned_columns())
    op.create_table("outbox_events", sa.Column("id", sa.String(64), primary_key=True), sa.Column("event_type", sa.String(100), nullable=False), sa.Column("aggregate_id", sa.String(64), nullable=False), sa.Column("payload", sa.JSON(), nullable=False), sa.Column("published", sa.Boolean(), nullable=False, server_default=sa.false()), *_owned_columns())
    op.create_table("idempotency_records", sa.Column("id", sa.String(64), primary_key=True), sa.Column("operation", sa.String(100), nullable=False), sa.Column("idempotency_key", sa.String(200), nullable=False), sa.Column("request_hash", sa.String(64), nullable=False), sa.Column("response_status", sa.Integer()), sa.Column("response_body", sa.JSON()), *_owned_columns(), sa.UniqueConstraint("tenant_id", "operation", "idempotency_key"))
    op.create_table("issue_definitions", sa.Column("id", sa.String(64), primary_key=True), sa.Column("fingerprint", sa.String(64), nullable=False), sa.Column("title", sa.String(500), nullable=False), sa.Column("tool", sa.String(100), nullable=False), sa.Column("rule_id", sa.String(200), nullable=False), sa.Column("tool_version", sa.String(100), nullable=False), sa.Column("database_version", sa.String(100), nullable=False), sa.Column("severity", sa.String(32), nullable=False), sa.Column("confidence", sa.String(32), nullable=False), *_owned_columns(), sa.UniqueConstraint("tenant_id", "fingerprint"))
    op.create_table("finding_instances", sa.Column("id", sa.String(64), primary_key=True), sa.Column("issue_definition_id", sa.String(64), sa.ForeignKey("issue_definitions.id"), nullable=False), sa.Column("affected_resource", sa.String(500), nullable=False), sa.Column("location", sa.String(1000), nullable=False), sa.Column("evidence_reference", sa.String(500)), sa.Column("redaction_state", sa.String(32), nullable=False), *_owned_columns(), sa.UniqueConstraint("tenant_id", "issue_definition_id", "affected_resource", "location"))

    # IMPORTANT: runtime role must be non-owner and must not have BYPASSRLS; provisioning never belongs in this secret-free migration.
    rls_statements = (
        "ALTER TABLE users ENABLE ROW LEVEL SECURITY", "ALTER TABLE users FORCE ROW LEVEL SECURITY", "CREATE POLICY users_tenant_isolation ON users USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK (tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE engagements ENABLE ROW LEVEL SECURITY", "ALTER TABLE engagements FORCE ROW LEVEL SECURITY", "CREATE POLICY engagements_tenant_isolation ON engagements USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK (tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE targets ENABLE ROW LEVEL SECURITY", "ALTER TABLE targets FORCE ROW LEVEL SECURITY", "CREATE POLICY targets_tenant_isolation ON targets USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK (tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE roe_versions ENABLE ROW LEVEL SECURITY", "ALTER TABLE roe_versions FORCE ROW LEVEL SECURITY", "CREATE POLICY roe_versions_tenant_isolation ON roe_versions USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK (tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE approvals ENABLE ROW LEVEL SECURITY", "ALTER TABLE approvals FORCE ROW LEVEL SECURITY", "CREATE POLICY approvals_tenant_isolation ON approvals USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK (tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE policy_references ENABLE ROW LEVEL SECURITY", "ALTER TABLE policy_references FORCE ROW LEVEL SECURITY", "CREATE POLICY policy_references_tenant_isolation ON policy_references USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK (tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE jobs ENABLE ROW LEVEL SECURITY", "ALTER TABLE jobs FORCE ROW LEVEL SECURITY", "CREATE POLICY jobs_tenant_isolation ON jobs USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK (tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY", "ALTER TABLE audit_events FORCE ROW LEVEL SECURITY", "CREATE POLICY audit_events_tenant_isolation ON audit_events USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK (tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE outbox_events ENABLE ROW LEVEL SECURITY", "ALTER TABLE outbox_events FORCE ROW LEVEL SECURITY", "CREATE POLICY outbox_events_tenant_isolation ON outbox_events USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK (tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE idempotency_records ENABLE ROW LEVEL SECURITY", "ALTER TABLE idempotency_records FORCE ROW LEVEL SECURITY", "CREATE POLICY idempotency_records_tenant_isolation ON idempotency_records USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK (tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE issue_definitions ENABLE ROW LEVEL SECURITY", "ALTER TABLE issue_definitions FORCE ROW LEVEL SECURITY", "CREATE POLICY issue_definitions_tenant_isolation ON issue_definitions USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK (tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE finding_instances ENABLE ROW LEVEL SECURITY", "ALTER TABLE finding_instances FORCE ROW LEVEL SECURITY", "CREATE POLICY finding_instances_tenant_isolation ON finding_instances USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK (tenant_id = current_setting('redagent.tenant_id', true))",
    )
    for statement in rls_statements:
        op.execute(statement)


def downgrade() -> None:
    for table_name in reversed(TENANT_TABLES):
        op.drop_table(table_name)
    op.drop_table("tenants")

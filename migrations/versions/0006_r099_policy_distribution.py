"""compat_099 policy bundle, agent, decision, and boundary receipt truth."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0006_r099_policy_distribution"
down_revision = "0005_r098_external_secret_leases"
branch_labels = None
depends_on = None


def upgrade() -> None:
    owned = (
        sa.Column("tenant_id", sa.String(64), nullable=False), sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "policy_bundle_revisions", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("revision_name", sa.String(100), nullable=False), sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column("artifact_sha256", sa.String(64), nullable=False), sa.Column("artifact_size", sa.BigInteger(), nullable=False),
        sa.Column("manifest_roots", postgresql.JSONB(astext_type=sa.Text()), nullable=False), sa.Column("rego_version", sa.Integer(), nullable=False),
        sa.Column("signing_key_id", sa.String(100), nullable=False), sa.Column("signing_scope", sa.String(100), nullable=False),
        sa.Column("signing_algorithm", sa.String(32), nullable=False), sa.Column("author_user_id", sa.String(64), nullable=False),
        sa.Column("reviewer_user_id", sa.String(64)), sa.Column("test_evidence_sha256", sa.String(64), nullable=False),
        sa.Column("coverage_basis_points", sa.Integer(), nullable=False), sa.Column("conformance_sha256", sa.String(64), nullable=False),
        sa.Column("bundle_status", sa.String(32), nullable=False), sa.Column("supersedes_revision", sa.String(100)), *owned,
        sa.UniqueConstraint("tenant_id", "revision_name", name="uq_policy_bundle_revisions_tenant_revision"),
    )
    op.create_table(
        "policy_bundle_promotions", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("bundle_revision", sa.String(100), nullable=False), sa.Column("previous_revision", sa.String(100)),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("required_agents", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("acknowledged_agents", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("promotion_state", sa.String(32), nullable=False), sa.Column("promoted_by_user_id", sa.String(64), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False), sa.Column("promoted_at", sa.DateTime(timezone=True)), *owned,
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_policy_bundle_promotions_tenant_idempotency"),
    )
    op.create_table(
        "policy_agent_status", sa.Column("id", sa.String(64), primary_key=True), sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("boundary", sa.String(32), nullable=False), sa.Column("active_revision", sa.String(100)),
        sa.Column("artifact_sha256", sa.String(64)),
        sa.Column("bundle_state", sa.String(32), nullable=False), sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("error_code", sa.String(100)), *owned,
        sa.UniqueConstraint("tenant_id", "agent_id", name="uq_policy_agent_status_tenant_agent"),
    )
    op.create_table(
        "policy_decisions", sa.Column("id", sa.String(64), primary_key=True), sa.Column("opa_decision_id", sa.String(100), nullable=False),
        sa.Column("bundle_revision", sa.String(100), nullable=False), sa.Column("input_hash", sa.String(64), nullable=False),
        sa.Column("boundary", sa.String(32), nullable=False), sa.Column("action", sa.String(100), nullable=False),
        sa.Column("subject_id", sa.String(64), nullable=False), sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("resource_id", sa.String(100), nullable=False), sa.Column("resource_version", sa.Integer()),
        sa.Column("allowed", sa.Boolean(), nullable=False), sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("obligations", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False), sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("correlation_id", sa.String(100), nullable=False), *owned,
        sa.UniqueConstraint("tenant_id", "opa_decision_id", name="uq_policy_decisions_tenant_opa_decision"),
    )
    op.create_table(
        "policy_boundary_receipts", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("decision_id", sa.String(64), nullable=False), sa.Column("boundary", sa.String(32), nullable=False),
        sa.Column("aggregate_type", sa.String(64), nullable=False), sa.Column("aggregate_id", sa.String(100), nullable=False),
        sa.Column("operation", sa.String(100), nullable=False), sa.Column("input_hash", sa.String(64), nullable=False),
        sa.Column("enforcement_outcome", sa.String(32), nullable=False), sa.Column("enforced_at", sa.DateTime(timezone=True), nullable=False), *owned,
        sa.ForeignKeyConstraint(["decision_id"], ["policy_decisions.id"]),
        sa.UniqueConstraint("tenant_id", "boundary", "aggregate_id", "operation", name="uq_policy_boundary_receipts_tenant_boundary_operation"),
    )
    op.create_table(
        "policy_log_receipts", sa.Column("id", sa.String(64), primary_key=True), sa.Column("opa_decision_id", sa.String(100), nullable=False),
        sa.Column("event_sha256", sa.String(64), nullable=False), sa.Column("masked", sa.Boolean(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False), sa.Column("reconciled_at", sa.DateTime(timezone=True)), *owned,
        sa.UniqueConstraint("tenant_id", "opa_decision_id", name="uq_policy_log_receipts_tenant_opa_decision"),
    )
    for table in (
        "policy_bundle_revisions", "policy_bundle_promotions", "policy_agent_status",
        "policy_decisions", "policy_boundary_receipts", "policy_log_receipts",
    ):
        _tenant_rls(table)


def downgrade() -> None:
    for table in (
        "policy_log_receipts", "policy_boundary_receipts", "policy_decisions", "policy_agent_status",
        "policy_bundle_promotions", "policy_bundle_revisions",
    ):
        op.drop_table(table)


def _tenant_rls(table: str) -> None:
    statements = {
        "policy_bundle_revisions": (
            'ALTER TABLE "policy_bundle_revisions" ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE "policy_bundle_revisions" FORCE ROW LEVEL SECURITY',
            'CREATE POLICY "policy_bundle_revisions_tenant_isolation" ON "policy_bundle_revisions" '
            "USING (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), '')) "
            "WITH CHECK (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), ''))",
        ),
        "policy_bundle_promotions": (
            'ALTER TABLE "policy_bundle_promotions" ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE "policy_bundle_promotions" FORCE ROW LEVEL SECURITY',
            'CREATE POLICY "policy_bundle_promotions_tenant_isolation" ON "policy_bundle_promotions" '
            "USING (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), '')) "
            "WITH CHECK (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), ''))",
        ),
        "policy_agent_status": (
            'ALTER TABLE "policy_agent_status" ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE "policy_agent_status" FORCE ROW LEVEL SECURITY',
            'CREATE POLICY "policy_agent_status_tenant_isolation" ON "policy_agent_status" '
            "USING (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), '')) "
            "WITH CHECK (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), ''))",
        ),
        "policy_decisions": (
            'ALTER TABLE "policy_decisions" ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE "policy_decisions" FORCE ROW LEVEL SECURITY',
            'CREATE POLICY "policy_decisions_tenant_isolation" ON "policy_decisions" '
            "USING (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), '')) "
            "WITH CHECK (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), ''))",
        ),
        "policy_boundary_receipts": (
            'ALTER TABLE "policy_boundary_receipts" ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE "policy_boundary_receipts" FORCE ROW LEVEL SECURITY',
            'CREATE POLICY "policy_boundary_receipts_tenant_isolation" ON "policy_boundary_receipts" '
            "USING (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), '')) "
            "WITH CHECK (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), ''))",
        ),
        "policy_log_receipts": (
            'ALTER TABLE "policy_log_receipts" ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE "policy_log_receipts" FORCE ROW LEVEL SECURITY',
            'CREATE POLICY "policy_log_receipts_tenant_isolation" ON "policy_log_receipts" '
            "USING (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), '')) "
            "WITH CHECK (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), ''))",
        ),
    }
    for statement in statements[table]:
        op.execute(statement)

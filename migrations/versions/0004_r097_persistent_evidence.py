"""compat_097 persistent evidence, object versions, derivatives, and custody."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0004_r097_persistent_evidence"
down_revision = "0003_r096_durable_workflows"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence_operations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("artifact_id", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("operation_state", sa.String(32), nullable=False),
        sa.Column("object_key", sa.String(1000), nullable=False),
        sa.Column("object_version_id", sa.String(256)),
        sa.Column("quarantine_reason", sa.String(200)),
        sa.Column("provider_error_code", sa.String(100)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_evidence_operations_tenant_idempotency"),
        sa.UniqueConstraint("tenant_id", "artifact_id", name="uq_evidence_operations_tenant_artifact"),
    )
    op.create_table(
        "evidence_artifacts",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("job_id", sa.String(64), nullable=False),
        sa.Column("producer_id", sa.String(64), nullable=False),
        sa.Column("object_key", sa.String(1000), nullable=False),
        sa.Column("object_version_id", sa.String(256), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("provider_checksum", sa.String(256), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("content_type", sa.String(100), nullable=False),
        sa.Column("artifact_class", sa.String(32), nullable=False),
        sa.Column("classification", sa.String(32), nullable=False),
        sa.Column("redaction_state", sa.String(32), nullable=False),
        sa.Column("retention_mode", sa.String(16), nullable=False),
        sa.Column("retain_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("legal_hold", sa.Boolean(), nullable=False),
        sa.Column("kms_reference", sa.String(200), nullable=False),
        sa.Column("attestation_hash", sa.String(64), nullable=False),
        sa.Column("policy_reference", sa.String(200), nullable=False),
        sa.Column("quarantine_reason", sa.String(200)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finalized_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "object_key", "object_version_id", name="uq_evidence_artifacts_tenant_object_version"),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"]),
    )
    op.create_table(
        "evidence_derivatives",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("artifact_id", sa.String(64), nullable=False),
        sa.Column("source_artifact_id", sa.String(64), nullable=False),
        sa.Column("source_object_version_id", sa.String(256), nullable=False),
        sa.Column("transform_name", sa.String(100), nullable=False),
        sa.Column("transform_version", sa.String(100), nullable=False),
        sa.Column("transform_config_hash", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artifact_id"], ["evidence_artifacts.id"]),
        sa.ForeignKeyConstraint(["source_artifact_id"], ["evidence_artifacts.id"]),
        sa.UniqueConstraint("tenant_id", "artifact_id", name="uq_evidence_derivatives_tenant_artifact"),
    )
    op.create_table(
        "evidence_custody_events",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("artifact_id", sa.String(64), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("actor_id", sa.String(64), nullable=False),
        sa.Column("attestation_hash", sa.String(64), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artifact_id"], ["evidence_artifacts.id"]),
    )
    op.create_table(
        "evidence_verifications",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("artifact_id", sa.String(64), nullable=False),
        sa.Column("object_key", sa.String(1000), nullable=False),
        sa.Column("object_version_id", sa.String(256), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("provider_checksum", sa.String(256), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False),
        sa.Column("quarantine_reason", sa.String(200)),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artifact_id"], ["evidence_artifacts.id"]),
    )
    _tenant_rls("evidence_operations")
    _tenant_rls("evidence_artifacts")
    _tenant_rls("evidence_derivatives")
    _tenant_rls("evidence_custody_events")
    _tenant_rls("evidence_verifications")


def downgrade() -> None:
    op.drop_table("evidence_verifications")
    op.drop_table("evidence_custody_events")
    op.drop_table("evidence_derivatives")
    op.drop_table("evidence_artifacts")
    op.drop_table("evidence_operations")


def _tenant_rls(table: str) -> None:
    statements = {
        "evidence_operations": (
            'ALTER TABLE "evidence_operations" ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE "evidence_operations" FORCE ROW LEVEL SECURITY',
        ),
        "evidence_artifacts": (
            'ALTER TABLE "evidence_artifacts" ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE "evidence_artifacts" FORCE ROW LEVEL SECURITY',
        ),
        "evidence_derivatives": (
            'ALTER TABLE "evidence_derivatives" ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE "evidence_derivatives" FORCE ROW LEVEL SECURITY',
        ),
        "evidence_custody_events": (
            'ALTER TABLE "evidence_custody_events" ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE "evidence_custody_events" FORCE ROW LEVEL SECURITY',
        ),
        "evidence_verifications": (
            'ALTER TABLE "evidence_verifications" ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE "evidence_verifications" FORCE ROW LEVEL SECURITY',
        ),
    }
    for statement in statements[table]:
        op.execute(statement)
    op.execute(
        f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" '
        "USING (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), '')) "
        "WITH CHECK (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), ''))"
    )

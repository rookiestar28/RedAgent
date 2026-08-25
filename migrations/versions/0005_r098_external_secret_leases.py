"""compat_098 opaque secret references, workload clients, and lease lifecycle."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0005_r098_external_secret_leases"
down_revision = "0004_r097_persistent_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "secret_references",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("owner_user_id", sa.String(64), nullable=False),
        sa.Column("reference_kind", sa.String(32), nullable=False),
        sa.Column("provider_alias", sa.String(64), nullable=False),
        sa.Column("role_reference", sa.String(200), nullable=False),
        sa.Column("allowed_capabilities", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("allowed_permissions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rotation_due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reference_status", sa.String(32), nullable=False),
        sa.Column("redaction_label", sa.String(200), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.UniqueConstraint("tenant_id", "id", name="uq_secret_references_tenant_reference"),
    )
    op.create_table(
        "secret_workload_clients",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("job_id", sa.String(64), nullable=False),
        sa.Column("capability", sa.String(64), nullable=False),
        sa.Column("attestation_fingerprint", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"]),
        sa.UniqueConstraint("tenant_id", "id", name="uq_secret_workload_clients_tenant_client"),
    )
    op.create_table(
        "secret_lease_operations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("lease_id", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("operation_state", sa.String(32), nullable=False),
        sa.Column("provider_lease_reference", sa.String(256)),
        sa.Column("failure_code", sa.String(100)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_secret_lease_operations_tenant_idempotency"),
        sa.UniqueConstraint("tenant_id", "lease_id", name="uq_secret_lease_operations_tenant_lease"),
    )
    op.create_table(
        "secret_leases",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("reference_id", sa.String(64), nullable=False),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("job_id", sa.String(64), nullable=False),
        sa.Column("workload_client_id", sa.String(64), nullable=False),
        sa.Column("capability", sa.String(64), nullable=False),
        sa.Column("permission_digest", sa.String(64), nullable=False),
        sa.Column("permission_count", sa.Integer(), nullable=False),
        sa.Column("provider_lease_reference", sa.String(256), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("renewed_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("renewable", sa.Boolean(), nullable=False),
        sa.Column("renewal_count", sa.Integer(), nullable=False),
        sa.Column("lease_state", sa.String(32), nullable=False),
        sa.Column("policy_reference", sa.String(200), nullable=False),
        sa.Column("roe_version_id", sa.String(64), nullable=False),
        sa.Column("failure_code", sa.String(100)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["reference_id"], ["secret_references.id"]),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"]),
        sa.ForeignKeyConstraint(["workload_client_id"], ["secret_workload_clients.id"]),
        sa.UniqueConstraint("tenant_id", "provider_lease_reference", name="uq_secret_leases_tenant_provider_lease"),
    )
    op.create_table(
        "secret_lease_events",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("lease_id", sa.String(64), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("actor_id", sa.String(64), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["lease_id"], ["secret_leases.id"]),
    )
    for table in (
        "secret_references", "secret_workload_clients", "secret_lease_operations",
        "secret_leases", "secret_lease_events",
    ):
        _tenant_rls(table)


def downgrade() -> None:
    op.drop_table("secret_lease_events")
    op.drop_table("secret_leases")
    op.drop_table("secret_lease_operations")
    op.drop_table("secret_workload_clients")
    op.drop_table("secret_references")


def _tenant_rls(table: str) -> None:
    statements = {
        "secret_references": (
            'ALTER TABLE "secret_references" ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE "secret_references" FORCE ROW LEVEL SECURITY',
        ),
        "secret_workload_clients": (
            'ALTER TABLE "secret_workload_clients" ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE "secret_workload_clients" FORCE ROW LEVEL SECURITY',
        ),
        "secret_lease_operations": (
            'ALTER TABLE "secret_lease_operations" ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE "secret_lease_operations" FORCE ROW LEVEL SECURITY',
        ),
        "secret_leases": (
            'ALTER TABLE "secret_leases" ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE "secret_leases" FORCE ROW LEVEL SECURITY',
        ),
        "secret_lease_events": (
            'ALTER TABLE "secret_lease_events" ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE "secret_lease_events" FORCE ROW LEVEL SECURITY',
        ),
    }
    for statement in statements[table]:
        op.execute(statement)
    op.execute(
        f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" '
        "USING (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), '')) "
        "WITH CHECK (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), ''))"
    )

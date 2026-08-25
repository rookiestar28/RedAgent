"""compat_108 cloud, Kubernetes, container, and IaC runtime connectors."""

from alembic import op
import sqlalchemy as sa


revision = "0015_r108_cloud"
down_revision = "0014_r107_network"
branch_labels = None
depends_on = None


TABLES = (
    "cloud_adapter_artifacts",
    "cloud_provider_profiles",
    "cloud_operation_manifests",
    "cloud_identity_bindings",
    "cloud_control_packs",
    "cloud_offline_artifacts",
    "cloud_collection_plans",
    "cloud_collection_runs",
    "cloud_snapshot_pages",
    "cloud_snapshot_resources",
    "cloud_check_results",
    "cloud_cleanup_receipts",
)


def upgrade() -> None:
    _create("cloud_adapter_artifacts", sa.Column("adapter_id", sa.String(100), nullable=False), sa.Column("adapter_version", sa.String(64), nullable=False), sa.Column("artifact_sha256", sa.String(64), nullable=False), sa.Column("license_id", sa.String(100), nullable=False), sa.Column("sbom_sha256", sa.String(64), nullable=False), sa.Column("execution_enabled", sa.Boolean(), nullable=False), sa.Column("production_qualified", sa.Boolean(), nullable=False), sa.UniqueConstraint("tenant_id", "adapter_id", "artifact_sha256", name="uq_cloud_adapter_tenant_artifact"))
    _create("cloud_provider_profiles", sa.Column("profile_id", sa.String(100), nullable=False), sa.Column("provider", sa.String(32), nullable=False), sa.Column("profile_sha256", sa.String(64), nullable=False), sa.Column("emulator_only", sa.Boolean(), nullable=False), sa.Column("limits", sa.JSON(), nullable=False), sa.Column("profile_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "profile_id", "profile_sha256", name="uq_cloud_profile_tenant_digest"))
    _create("cloud_operation_manifests", sa.Column("profile_record_id", sa.String(64), sa.ForeignKey("cloud_provider_profiles.id"), nullable=False), sa.Column("operation_id", sa.String(100), nullable=False), sa.Column("action", sa.String(200), nullable=False), sa.Column("resource_scope", sa.String(500), nullable=False), sa.Column("data_class", sa.String(64), nullable=False), sa.Column("mutation", sa.Boolean(), nullable=False), sa.Column("page_cost", sa.Integer(), nullable=False), sa.UniqueConstraint("tenant_id", "profile_record_id", "operation_id", name="uq_cloud_operation_tenant_profile"))
    _create("cloud_identity_bindings", sa.Column("binding_id", sa.String(100), nullable=False), sa.Column("profile_record_id", sa.String(64), sa.ForeignKey("cloud_provider_profiles.id"), nullable=False), sa.Column("provider", sa.String(32), nullable=False), sa.Column("expected_tenant", sa.String(200), nullable=False), sa.Column("expected_parent", sa.String(200)), sa.Column("permissions", sa.JSON(), nullable=False), sa.Column("data_classes", sa.JSON(), nullable=False), sa.Column("permission_digest", sa.String(64), nullable=False), sa.Column("binding_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "binding_id", name="uq_cloud_identity_tenant_binding"))
    _create("cloud_control_packs", sa.Column("pack_id", sa.String(100), nullable=False), sa.Column("pack_version", sa.String(64), nullable=False), sa.Column("pack_sha256", sa.String(64), nullable=False), sa.Column("database_sha256", sa.String(64), nullable=False), sa.Column("data_classes", sa.JSON(), nullable=False), sa.Column("pack_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "pack_id", "pack_sha256", name="uq_cloud_pack_tenant_digest"))
    _create("cloud_offline_artifacts", sa.Column("input_id", sa.String(100), nullable=False), sa.Column("input_kind", sa.String(32), nullable=False), sa.Column("input_sha256", sa.String(64), nullable=False), sa.Column("file_count", sa.Integer(), nullable=False), sa.Column("size_bytes", sa.BigInteger(), nullable=False), sa.Column("network_allowed", sa.Boolean(), nullable=False), sa.Column("artifact_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "input_id", "input_sha256", name="uq_cloud_offline_tenant_digest"))
    _create("cloud_collection_plans", sa.Column("plan_id", sa.String(100), nullable=False), sa.Column("profile_record_id", sa.String(64), sa.ForeignKey("cloud_provider_profiles.id"), nullable=False), sa.Column("identity_binding_id", sa.String(64), sa.ForeignKey("cloud_identity_bindings.id"), nullable=False), sa.Column("policy_decision_id", sa.String(100), nullable=False), sa.Column("policy_revision", sa.String(100), nullable=False), sa.Column("reservation_id", sa.String(100), nullable=False), sa.Column("credential_lease_id", sa.String(100), nullable=False), sa.Column("plan_sha256", sa.String(64), nullable=False), sa.Column("plan_state", sa.String(32), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "plan_id", name="uq_cloud_plan_tenant_id"))
    _create("cloud_collection_runs", sa.Column("run_id", sa.String(100), nullable=False), sa.Column("plan_record_id", sa.String(64), sa.ForeignKey("cloud_collection_plans.id"), nullable=False), sa.Column("job_id", sa.String(100), nullable=False), sa.Column("runner_id", sa.String(100), nullable=False), sa.Column("run_state", sa.String(32), nullable=False), sa.Column("complete", sa.Boolean(), nullable=False), sa.Column("partial_reasons", sa.JSON(), nullable=False), sa.Column("snapshot_sha256", sa.String(64)), sa.UniqueConstraint("tenant_id", "run_id", name="uq_cloud_run_tenant_id"))
    _create("cloud_snapshot_pages", sa.Column("run_record_id", sa.String(64), sa.ForeignKey("cloud_collection_runs.id"), nullable=False), sa.Column("operation_id", sa.String(100), nullable=False), sa.Column("page_index", sa.Integer(), nullable=False), sa.Column("response_sha256", sa.String(64), nullable=False), sa.Column("response_bytes", sa.BigInteger(), nullable=False), sa.Column("partial_reason", sa.String(100)), sa.UniqueConstraint("tenant_id", "run_record_id", "operation_id", "page_index", name="uq_cloud_page_tenant_run_operation"))
    _create("cloud_snapshot_resources", sa.Column("run_record_id", sa.String(64), sa.ForeignKey("cloud_collection_runs.id"), nullable=False), sa.Column("operation_id", sa.String(100), nullable=False), sa.Column("resource_id", sa.String(500), nullable=False), sa.Column("resource_sha256", sa.String(64), nullable=False), sa.Column("data_class", sa.String(64), nullable=False), sa.Column("redaction_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "run_record_id", "operation_id", "resource_id", name="uq_cloud_resource_tenant_run_resource"))
    _create("cloud_check_results", sa.Column("run_record_id", sa.String(64), sa.ForeignKey("cloud_collection_runs.id"), nullable=False), sa.Column("result_id", sa.String(100), nullable=False), sa.Column("control_pack_id", sa.String(100), nullable=False), sa.Column("check_id", sa.String(100), nullable=False), sa.Column("resource_id", sa.String(500), nullable=False), sa.Column("passed", sa.Boolean(), nullable=False), sa.Column("severity", sa.String(32), nullable=False), sa.Column("evidence_instance_id", sa.String(100)), sa.UniqueConstraint("tenant_id", "result_id", name="uq_cloud_result_tenant_id"))
    _create("cloud_cleanup_receipts", sa.Column("run_record_id", sa.String(64), sa.ForeignKey("cloud_collection_runs.id"), nullable=False), sa.Column("receipt_id", sa.String(100), nullable=False), sa.Column("lease_revoked", sa.Boolean(), nullable=False), sa.Column("new_requests_blocked", sa.Boolean(), nullable=False), sa.Column("residual_resource_count", sa.Integer(), nullable=False), sa.Column("inventory_sha256", sa.String(64), nullable=False), sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_cloud_cleanup_tenant_id"))
    for table in TABLES:
        _tenant_rls(table)


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f'DROP TABLE IF EXISTS "{table}"')


def _create(name: str, *columns: object) -> None:
    op.create_table(name, sa.Column("id", sa.String(64), primary_key=True), *columns, *_owned())


def _owned() -> tuple[sa.Column, ...]:
    return (
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def _tenant_rls(table: str) -> None:
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
    op.execute(
        f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" '
        "USING (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), '')) "
        "WITH CHECK (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), ''))"
    )

"""compat_107 restricted network and infrastructure assessment runtime."""

from alembic import op
import sqlalchemy as sa


revision = "0014_r107_network"
down_revision = "0013_r106_api_diff"
branch_labels = None
depends_on = None


TABLES = (
    "network_engine_artifacts",
    "network_adapter_declarations",
    "network_profiles",
    "network_topology_attestations",
    "network_target_sets",
    "network_plans",
    "network_plan_tuples",
    "network_runs",
    "network_gateway_decisions",
    "network_observations",
    "network_cancellation_receipts",
    "network_cleanup_receipts",
)


def upgrade() -> None:
    _create("network_engine_artifacts",
        sa.Column("engine_id", sa.String(100), nullable=False),
        sa.Column("engine_version", sa.String(32), nullable=False),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("sbom_sha256", sa.String(64), nullable=False),
        sa.Column("license_review_sha256", sa.String(64), nullable=False),
        sa.Column("vulnerability_review", sa.String(64), nullable=False),
        sa.Column("production_qualified", sa.Boolean(), nullable=False),
        sa.Column("artifact_state", sa.String(32), nullable=False),
        sa.UniqueConstraint("tenant_id", "engine_id", "artifact_sha256", name="uq_network_engine_tenant_artifact"))
    _create("network_adapter_declarations",
        sa.Column("adapter_id", sa.String(100), nullable=False),
        sa.Column("adapter_version", sa.String(32), nullable=False),
        sa.Column("source_url", sa.String(500), nullable=False),
        sa.Column("license_id", sa.String(100), nullable=False),
        sa.Column("execution_enabled", sa.Boolean(), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("declaration_state", sa.String(32), nullable=False),
        sa.UniqueConstraint("tenant_id", "adapter_id", "adapter_version", name="uq_network_adapter_tenant_version"))
    _create("network_profiles",
        sa.Column("profile_id", sa.String(100), nullable=False),
        sa.Column("profile_revision", sa.Integer(), nullable=False),
        sa.Column("engine_record_id", sa.String(64), sa.ForeignKey("network_engine_artifacts.id"), nullable=False),
        sa.Column("profile_sha256", sa.String(64), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("limits", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("profile_state", sa.String(32), nullable=False),
        sa.UniqueConstraint("tenant_id", "profile_id", "profile_revision", name="uq_network_profile_tenant_revision"))
    _create("network_topology_attestations",
        sa.Column("topology_id", sa.String(100), nullable=False),
        sa.Column("topology_sha256", sa.String(64), nullable=False),
        sa.Column("route_sha256", sa.String(64), nullable=False),
        sa.Column("network_id", sa.String(100), nullable=False),
        sa.Column("non_production", sa.Boolean(), nullable=False),
        sa.Column("no_public_route", sa.Boolean(), nullable=False),
        sa.Column("no_direct_target_route", sa.Boolean(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "topology_id", "topology_sha256", name="uq_network_topology_tenant_digest"))
    _create("network_target_sets",
        sa.Column("target_set_id", sa.String(100), nullable=False),
        sa.Column("topology_record_id", sa.String(64), sa.ForeignKey("network_topology_attestations.id"), nullable=False),
        sa.Column("target_set_sha256", sa.String(64), nullable=False),
        sa.Column("literal_targets", sa.JSON(), nullable=False),
        sa.Column("allowed_ports", sa.JSON(), nullable=False),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("target_set_state", sa.String(32), nullable=False),
        sa.UniqueConstraint("tenant_id", "target_set_id", "target_set_sha256", name="uq_network_target_set_tenant_digest"))
    _create("network_plans",
        sa.Column("plan_id", sa.String(100), nullable=False),
        sa.Column("profile_record_id", sa.String(64), sa.ForeignKey("network_profiles.id"), nullable=False),
        sa.Column("target_set_record_id", sa.String(64), sa.ForeignKey("network_target_sets.id"), nullable=False),
        sa.Column("policy_decision_id", sa.String(100), nullable=False),
        sa.Column("policy_revision", sa.String(100), nullable=False),
        sa.Column("roe_version_id", sa.String(100), nullable=False),
        sa.Column("reservation_id", sa.String(100), nullable=False),
        sa.Column("plan_sha256", sa.String(64), nullable=False),
        sa.Column("budgets", sa.JSON(), nullable=False),
        sa.Column("plan_state", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "plan_id", name="uq_network_plan_tenant_id"))
    _create("network_plan_tuples",
        sa.Column("plan_record_id", sa.String(64), sa.ForeignKey("network_plans.id"), nullable=False),
        sa.Column("tuple_id", sa.String(100), nullable=False),
        sa.Column("literal_ip", sa.String(64), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("tuple_sha256", sa.String(64), nullable=False),
        sa.Column("tuple_state", sa.String(32), nullable=False),
        sa.CheckConstraint("port >= 1 AND port <= 65535", name="ck_network_tuple_port"),
        sa.UniqueConstraint("tenant_id", "plan_record_id", "tuple_id", name="uq_network_tuple_tenant_plan_tuple"))
    _create("network_runs",
        sa.Column("run_id", sa.String(100), nullable=False),
        sa.Column("plan_record_id", sa.String(64), sa.ForeignKey("network_plans.id"), nullable=False),
        sa.Column("job_id", sa.String(100), nullable=False),
        sa.Column("runner_id", sa.String(100), nullable=False),
        sa.Column("run_state", sa.String(32), nullable=False),
        sa.Column("completed_tuples", sa.Integer(), nullable=False),
        sa.Column("total_tuples", sa.Integer(), nullable=False),
        sa.Column("partial", sa.Boolean(), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.UniqueConstraint("tenant_id", "run_id", name="uq_network_run_tenant_id"))
    _create("network_gateway_decisions",
        sa.Column("run_record_id", sa.String(64), sa.ForeignKey("network_runs.id"), nullable=False),
        sa.Column("decision_id", sa.String(100), nullable=False),
        sa.Column("tuple_id", sa.String(100), nullable=False),
        sa.Column("allowed", sa.Boolean(), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("data_bytes", sa.BigInteger(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "decision_id", name="uq_network_decision_tenant_id"))
    _create("network_observations",
        sa.Column("run_record_id", sa.String(64), sa.ForeignKey("network_runs.id"), nullable=False),
        sa.Column("observation_id", sa.String(100), nullable=False),
        sa.Column("tuple_id", sa.String(100), nullable=False),
        sa.Column("connection_state", sa.String(32), nullable=False),
        sa.Column("latency_bucket", sa.String(32), nullable=False),
        sa.Column("service_class", sa.String(64), nullable=False),
        sa.Column("sample_sha256", sa.String(64), nullable=False),
        sa.Column("uncertainty", sa.String(32), nullable=False),
        sa.Column("redaction_state", sa.String(32), nullable=False),
        sa.Column("evidence_instance_id", sa.String(100)),
        sa.UniqueConstraint("tenant_id", "observation_id", name="uq_network_observation_tenant_id"))
    _create("network_cancellation_receipts",
        sa.Column("run_record_id", sa.String(64), sa.ForeignKey("network_runs.id"), nullable=False),
        sa.Column("receipt_id", sa.String(100), nullable=False),
        sa.Column("gateway_blocked", sa.Boolean(), nullable=False),
        sa.Column("worker_stop_attempted", sa.Boolean(), nullable=False),
        sa.Column("worker_stop_acknowledged", sa.Boolean(), nullable=False),
        sa.Column("forced_termination", sa.Boolean(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_network_cancel_tenant_id"))
    _create("network_cleanup_receipts",
        sa.Column("run_record_id", sa.String(64), sa.ForeignKey("network_runs.id"), nullable=False),
        sa.Column("receipt_id", sa.String(100), nullable=False),
        sa.Column("container_count", sa.Integer(), nullable=False),
        sa.Column("network_count", sa.Integer(), nullable=False),
        sa.Column("transient_file_count", sa.Integer(), nullable=False),
        sa.Column("residual_resource_count", sa.Integer(), nullable=False),
        sa.Column("inventory_sha256", sa.String(64), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_network_cleanup_tenant_id"))
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

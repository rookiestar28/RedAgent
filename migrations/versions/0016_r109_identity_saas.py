"""compat_109 enterprise identity and SaaS posture runtime connectors."""

from alembic import op
import sqlalchemy as sa


revision = "0016_r109_identity"
down_revision = "0015_r108_cloud"
branch_labels = None
depends_on = None


TABLES = (
    "identity_adapter_artifacts", "identity_provider_profiles", "identity_operation_manifests",
    "identity_tenant_bindings", "identity_baseline_artifacts", "identity_collection_plans",
    "identity_collection_runs", "identity_snapshot_pages", "identity_snapshot_resources",
    "identity_baseline_evaluations", "identity_exception_annotations", "identity_exception_approvals",
    "identity_graph_approvals", "identity_graph_nodes", "identity_graph_edges",
    "identity_cleanup_receipts",
)


def upgrade() -> None:
    _create("identity_adapter_artifacts", sa.Column("adapter_id", sa.String(100), nullable=False), sa.Column("artifact_sha256", sa.String(64), nullable=False), sa.Column("execution_enabled", sa.Boolean(), nullable=False), sa.Column("production_qualified", sa.Boolean(), nullable=False), sa.UniqueConstraint("tenant_id", "adapter_id", "artifact_sha256", name="uq_identity_adapter_tenant_digest"))
    _create("identity_provider_profiles", sa.Column("profile_id", sa.String(100), nullable=False), sa.Column("provider", sa.String(32), nullable=False), sa.Column("profile_sha256", sa.String(64), nullable=False), sa.Column("emulator_only", sa.Boolean(), nullable=False), sa.Column("limits", sa.JSON(), nullable=False), sa.Column("retention_days", sa.Integer(), nullable=False), sa.Column("profile_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "profile_id", "profile_sha256", name="uq_identity_profile_tenant_digest"))
    _create("identity_operation_manifests", sa.Column("profile_record_id", sa.String(64), sa.ForeignKey("identity_provider_profiles.id"), nullable=False), sa.Column("operation_id", sa.String(100), nullable=False), sa.Column("method", sa.String(16), nullable=False), sa.Column("api_version", sa.String(32), nullable=False), sa.Column("permission_scope", sa.String(300), nullable=False), sa.Column("role_permission", sa.String(300), nullable=False), sa.Column("selected_fields", sa.JSON(), nullable=False), sa.Column("data_class", sa.String(64), nullable=False), sa.Column("graph_eligible", sa.Boolean(), nullable=False), sa.UniqueConstraint("tenant_id", "profile_record_id", "operation_id", name="uq_identity_operation_tenant_profile"))
    _create("identity_tenant_bindings", sa.Column("binding_id", sa.String(100), nullable=False), sa.Column("profile_record_id", sa.String(64), sa.ForeignKey("identity_provider_profiles.id"), nullable=False), sa.Column("provider_tenant_id", sa.String(200), nullable=False), sa.Column("audience", sa.String(200), nullable=False), sa.Column("consent_mode", sa.String(32), nullable=False), sa.Column("scopes", sa.JSON(), nullable=False), sa.Column("role_permissions", sa.JSON(), nullable=False), sa.Column("permission_digest", sa.String(64), nullable=False), sa.Column("binding_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "binding_id", name="uq_identity_binding_tenant_id"))
    _create("identity_baseline_artifacts", sa.Column("baseline_id", sa.String(100), nullable=False), sa.Column("baseline_version", sa.String(64), nullable=False), sa.Column("baseline_sha256", sa.String(64), nullable=False), sa.Column("schema_sha256", sa.String(64), nullable=False), sa.Column("baseline_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "baseline_id", "baseline_sha256", name="uq_identity_baseline_tenant_digest"))
    _create("identity_collection_plans", sa.Column("plan_id", sa.String(100), nullable=False), sa.Column("profile_record_id", sa.String(64), sa.ForeignKey("identity_provider_profiles.id"), nullable=False), sa.Column("binding_record_id", sa.String(64), sa.ForeignKey("identity_tenant_bindings.id"), nullable=False), sa.Column("baseline_record_id", sa.String(64), sa.ForeignKey("identity_baseline_artifacts.id"), nullable=False), sa.Column("policy_decision_id", sa.String(100), nullable=False), sa.Column("reservation_id", sa.String(100), nullable=False), sa.Column("credential_lease_id", sa.String(100), nullable=False), sa.Column("plan_sha256", sa.String(64), nullable=False), sa.Column("plan_state", sa.String(32), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "plan_id", name="uq_identity_plan_tenant_id"))
    _create("identity_collection_runs", sa.Column("run_id", sa.String(100), nullable=False), sa.Column("plan_record_id", sa.String(64), sa.ForeignKey("identity_collection_plans.id"), nullable=False), sa.Column("job_id", sa.String(100), nullable=False), sa.Column("runner_id", sa.String(100), nullable=False), sa.Column("run_state", sa.String(32), nullable=False), sa.Column("complete", sa.Boolean(), nullable=False), sa.Column("partial_reasons", sa.JSON(), nullable=False), sa.Column("snapshot_sha256", sa.String(64)), sa.UniqueConstraint("tenant_id", "run_id", name="uq_identity_run_tenant_id"))
    _create("identity_snapshot_pages", sa.Column("run_record_id", sa.String(64), sa.ForeignKey("identity_collection_runs.id"), nullable=False), sa.Column("operation_id", sa.String(100), nullable=False), sa.Column("page_index", sa.Integer(), nullable=False), sa.Column("page_sha256", sa.String(64), nullable=False), sa.Column("partial_reason", sa.String(100)), sa.UniqueConstraint("tenant_id", "run_record_id", "operation_id", "page_index", name="uq_identity_page_tenant_run"))
    _create("identity_snapshot_resources", sa.Column("run_record_id", sa.String(64), sa.ForeignKey("identity_collection_runs.id"), nullable=False), sa.Column("operation_id", sa.String(100), nullable=False), sa.Column("resource_id", sa.String(300), nullable=False), sa.Column("resource_sha256", sa.String(64), nullable=False), sa.Column("data_class", sa.String(64), nullable=False), sa.Column("redaction_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "run_record_id", "operation_id", "resource_id", name="uq_identity_resource_tenant_run"))
    _create("identity_baseline_evaluations", sa.Column("run_record_id", sa.String(64), sa.ForeignKey("identity_collection_runs.id"), nullable=False), sa.Column("evaluation_id", sa.String(100), nullable=False), sa.Column("control_id", sa.String(100), nullable=False), sa.Column("resource_id", sa.String(300), nullable=False), sa.Column("passed", sa.Boolean(), nullable=False), sa.Column("evaluation_sha256", sa.String(64), nullable=False), sa.Column("evidence_instance_id", sa.String(100)), sa.UniqueConstraint("tenant_id", "evaluation_id", name="uq_identity_evaluation_tenant_id"))
    _create("identity_exception_annotations", sa.Column("exception_id", sa.String(100), nullable=False), sa.Column("evaluation_record_id", sa.String(64), sa.ForeignKey("identity_baseline_evaluations.id"), nullable=False), sa.Column("control_id", sa.String(100), nullable=False), sa.Column("resource_id", sa.String(300), nullable=False), sa.Column("justification", sa.Text(), nullable=False), sa.Column("requested_by", sa.String(64), nullable=False), sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("supersedes_exception_id", sa.String(100)), sa.UniqueConstraint("tenant_id", "exception_id", name="uq_identity_exception_tenant_id"))
    _create("identity_exception_approvals", sa.Column("exception_record_id", sa.String(64), sa.ForeignKey("identity_exception_annotations.id"), nullable=False), sa.Column("approval_id", sa.String(100), nullable=False), sa.Column("approved_by", sa.String(64), nullable=False), sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False), sa.Column("approval_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "approval_id", name="uq_identity_exception_approval_tenant_id"))
    _create("identity_graph_approvals", sa.Column("approval_id", sa.String(100), nullable=False), sa.Column("approved_by", sa.String(64), nullable=False), sa.Column("restricted_role", sa.String(64), nullable=False), sa.Column("export_allowed", sa.Boolean(), nullable=False), sa.Column("model_access_allowed", sa.Boolean(), nullable=False), sa.Column("retention_hours", sa.Integer(), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "approval_id", name="uq_identity_graph_approval_tenant_id"))
    _create("identity_graph_nodes", sa.Column("approval_record_id", sa.String(64), sa.ForeignKey("identity_graph_approvals.id"), nullable=False), sa.Column("node_id", sa.String(100), nullable=False), sa.Column("node_type", sa.String(32), nullable=False), sa.Column("node_sha256", sa.String(64), nullable=False), sa.UniqueConstraint("tenant_id", "approval_record_id", "node_id", name="uq_identity_graph_node_tenant_id"))
    _create("identity_graph_edges", sa.Column("approval_record_id", sa.String(64), sa.ForeignKey("identity_graph_approvals.id"), nullable=False), sa.Column("edge_id", sa.String(100), nullable=False), sa.Column("source_id", sa.String(100), nullable=False), sa.Column("target_id", sa.String(100), nullable=False), sa.Column("edge_type", sa.String(64), nullable=False), sa.UniqueConstraint("tenant_id", "approval_record_id", "edge_id", name="uq_identity_graph_edge_tenant_id"))
    _create("identity_cleanup_receipts", sa.Column("run_record_id", sa.String(64), sa.ForeignKey("identity_collection_runs.id"), nullable=False), sa.Column("receipt_id", sa.String(100), nullable=False), sa.Column("lease_revoked", sa.Boolean(), nullable=False), sa.Column("new_requests_blocked", sa.Boolean(), nullable=False), sa.Column("graph_expired", sa.Boolean(), nullable=False), sa.Column("residual_resource_count", sa.Integer(), nullable=False), sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_identity_cleanup_tenant_id"))
    for table in TABLES:
        _tenant_rls(table)


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f'DROP TABLE IF EXISTS "{table}"')


def _create(name: str, *columns: object) -> None:
    op.create_table(name, sa.Column("id", sa.String(64), primary_key=True), *columns, *_owned())


def _owned() -> tuple[sa.Column, ...]:
    return (sa.Column("tenant_id", sa.String(64), nullable=False), sa.Column("version", sa.Integer(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))


def _tenant_rls(table: str) -> None:
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
    op.execute(f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" USING (tenant_id = NULLIF(current_setting(\'redagent.tenant_id\', true), \'\')) WITH CHECK (tenant_id = NULLIF(current_setting(\'redagent.tenant_id\', true), \'\'))')

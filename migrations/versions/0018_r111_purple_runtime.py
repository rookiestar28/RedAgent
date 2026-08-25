"""compat_111 lab-only adversary-emulation and purple-team telemetry runtime."""

from alembic import op
import sqlalchemy as sa


revision = "0018_r111_purple"
down_revision = "0017_r110_artifact"
branch_labels = None
depends_on = None


TABLES = (
    "purple_adapter_artifacts", "purple_abilities", "purple_ability_phases", "purple_detection_expectations",
    "purple_lab_bindings", "purple_approvals", "purple_execution_plans", "purple_runs", "purple_snapshots",
    "purple_action_receipts", "purple_telemetry_events", "purple_cleanup_receipts", "purple_teardown_receipts",
    "purple_rehearsal_receipts",
)


def upgrade() -> None:
    _create("purple_adapter_artifacts", sa.Column("adapter_id", sa.String(100), nullable=False), sa.Column("adapter_sha256", sa.String(64), nullable=False), sa.Column("owned", sa.Boolean(), nullable=False), sa.Column("external_execution_allowed", sa.Boolean(), nullable=False), sa.Column("artifact_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "adapter_id", "adapter_sha256", name="uq_purple_adapter_tenant_digest"))
    _create("purple_abilities", sa.Column("ability_id", sa.String(100), nullable=False), sa.Column("ability_sha256", sa.String(64), nullable=False), sa.Column("adapter_record_id", sa.String(64), sa.ForeignKey("purple_adapter_artifacts.id"), nullable=False), sa.Column("attack_version", sa.String(64), nullable=False), sa.Column("attack_technique_id", sa.String(32), nullable=False), sa.Column("platform", sa.String(100), nullable=False), sa.Column("content_sha256", sa.String(64), nullable=False), sa.Column("network_allowed", sa.Boolean(), nullable=False), sa.Column("subprocess_allowed", sa.Boolean(), nullable=False), sa.Column("ability_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "ability_id", "ability_sha256", name="uq_purple_ability_tenant_digest"))
    _create("purple_ability_phases", sa.Column("ability_record_id", sa.String(64), sa.ForeignKey("purple_abilities.id"), nullable=False), sa.Column("phase_order", sa.Integer(), nullable=False), sa.Column("phase_kind", sa.String(32), nullable=False), sa.Column("operation_id", sa.String(100), nullable=False), sa.Column("operation_sha256", sa.String(64), nullable=False), sa.UniqueConstraint("tenant_id", "ability_record_id", "phase_order", name="uq_purple_phase_tenant_order"))
    _create("purple_detection_expectations", sa.Column("ability_record_id", sa.String(64), sa.ForeignKey("purple_abilities.id"), nullable=False), sa.Column("strategy_id", sa.String(100), nullable=False), sa.Column("analytic_id", sa.String(100), nullable=False), sa.Column("event_schema", sa.String(100), nullable=False), sa.Column("collector_id", sa.String(100), nullable=False), sa.Column("expectation_sha256", sa.String(64), nullable=False), sa.UniqueConstraint("tenant_id", "ability_record_id", "analytic_id", name="uq_purple_detection_tenant_analytic"))
    _create("purple_lab_bindings", sa.Column("binding_id", sa.String(100), nullable=False), sa.Column("target_id", sa.String(100), nullable=False), sa.Column("runner_id", sa.String(100), nullable=False), sa.Column("snapshot_sha256", sa.String(64), nullable=False), sa.Column("telemetry_collector_id", sa.String(100), nullable=False), sa.Column("disposable", sa.Boolean(), nullable=False), sa.Column("production", sa.Boolean(), nullable=False), sa.Column("egress_allowed", sa.Boolean(), nullable=False), sa.Column("binding_state", sa.String(32), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "binding_id", name="uq_purple_lab_tenant_id"))
    _create("purple_approvals", sa.Column("approval_id", sa.String(100), nullable=False), sa.Column("ability_record_id", sa.String(64), sa.ForeignKey("purple_abilities.id"), nullable=False), sa.Column("lab_binding_record_id", sa.String(64), sa.ForeignKey("purple_lab_bindings.id"), nullable=False), sa.Column("ability_sha256", sa.String(64), nullable=False), sa.Column("adapter_sha256", sa.String(64), nullable=False), sa.Column("lab_snapshot_sha256", sa.String(64), nullable=False), sa.Column("requester_id", sa.String(64), nullable=False), sa.Column("approver_id", sa.String(64), nullable=False), sa.Column("executor_id", sa.String(64), nullable=False), sa.Column("approval_state", sa.String(32), nullable=False), sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "approval_id", name="uq_purple_approval_tenant_id"))
    _create("purple_execution_plans", sa.Column("plan_id", sa.String(100), nullable=False), sa.Column("ability_record_id", sa.String(64), sa.ForeignKey("purple_abilities.id"), nullable=False), sa.Column("lab_binding_record_id", sa.String(64), sa.ForeignKey("purple_lab_bindings.id"), nullable=False), sa.Column("approval_record_id", sa.String(64), sa.ForeignKey("purple_approvals.id"), nullable=False), sa.Column("policy_decision_id", sa.String(100), nullable=False), sa.Column("roe_revision", sa.String(100), nullable=False), sa.Column("reservation_id", sa.String(100), nullable=False), sa.Column("lease_id", sa.String(100), nullable=False), sa.Column("kill_switch_id", sa.String(100), nullable=False), sa.Column("quota_id", sa.String(100), nullable=False), sa.Column("plan_sha256", sa.String(64), nullable=False), sa.Column("plan_state", sa.String(32), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "plan_id", name="uq_purple_plan_tenant_id"))
    _create("purple_runs", sa.Column("run_id", sa.String(100), nullable=False), sa.Column("plan_record_id", sa.String(64), sa.ForeignKey("purple_execution_plans.id"), nullable=False), sa.Column("job_id", sa.String(100), nullable=False), sa.Column("runner_id", sa.String(100), nullable=False), sa.Column("run_state", sa.String(32), nullable=False), sa.Column("dispatch_blocked", sa.Boolean(), nullable=False), sa.Column("detection_observed", sa.Boolean(), nullable=False), sa.Column("cleanup_complete", sa.Boolean(), nullable=False), sa.Column("teardown_verified", sa.Boolean(), nullable=False), sa.Column("failure_code", sa.String(100)), sa.UniqueConstraint("tenant_id", "run_id", name="uq_purple_run_tenant_id"))
    _create("purple_snapshots", sa.Column("run_record_id", sa.String(64), sa.ForeignKey("purple_runs.id"), nullable=False), sa.Column("snapshot_kind", sa.String(32), nullable=False), sa.Column("entry_count", sa.Integer(), nullable=False), sa.Column("inventory_sha256", sa.String(64), nullable=False), sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "run_record_id", "snapshot_kind", name="uq_purple_snapshot_tenant_kind"))
    _create("purple_action_receipts", sa.Column("run_record_id", sa.String(64), sa.ForeignKey("purple_runs.id"), nullable=False), sa.Column("phase_kind", sa.String(32), nullable=False), sa.Column("operation_id", sa.String(100), nullable=False), sa.Column("artifact_sha256", sa.String(64), nullable=False), sa.Column("network_contact_count", sa.Integer(), nullable=False), sa.Column("subprocess_count", sa.Integer(), nullable=False), sa.Column("privilege_use_count", sa.Integer(), nullable=False), sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "run_record_id", "phase_kind", name="uq_purple_action_tenant_phase"))
    _create("purple_telemetry_events", sa.Column("run_record_id", sa.String(64), sa.ForeignKey("purple_runs.id"), nullable=False), sa.Column("collector_id", sa.String(100), nullable=False), sa.Column("event_schema", sa.String(100), nullable=False), sa.Column("analytic_id", sa.String(100), nullable=False), sa.Column("event_sha256", sa.String(64), nullable=False), sa.Column("integrity_verified", sa.Boolean(), nullable=False), sa.Column("correlated", sa.Boolean(), nullable=False), sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "run_record_id", "event_sha256", name="uq_purple_telemetry_tenant_event"))
    _create("purple_cleanup_receipts", sa.Column("run_record_id", sa.String(64), sa.ForeignKey("purple_runs.id"), nullable=False), sa.Column("receipt_id", sa.String(100), nullable=False), sa.Column("marker_removed", sa.Boolean(), nullable=False), sa.Column("residual_resource_count", sa.Integer(), nullable=False), sa.Column("after_inventory_sha256", sa.String(64), nullable=False), sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_purple_cleanup_tenant_id"))
    _create("purple_teardown_receipts", sa.Column("run_record_id", sa.String(64), sa.ForeignKey("purple_runs.id"), nullable=False), sa.Column("receipt_id", sa.String(100), nullable=False), sa.Column("lease_revoked", sa.Boolean(), nullable=False), sa.Column("dispatch_blocked", sa.Boolean(), nullable=False), sa.Column("kill_acknowledged", sa.Boolean(), nullable=False), sa.Column("residual_resource_count", sa.Integer(), nullable=False), sa.Column("teardown_verified", sa.Boolean(), nullable=False), sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_purple_teardown_tenant_id"))
    _create("purple_rehearsal_receipts", sa.Column("rehearsal_id", sa.String(100), nullable=False), sa.Column("ability_sha256", sa.String(64), nullable=False), sa.Column("plan_sha256", sa.String(64), nullable=False), sa.Column("telemetry_event_sha256", sa.String(64), nullable=False), sa.Column("cleanup_sha256", sa.String(64), nullable=False), sa.Column("external_contact_count", sa.Integer(), nullable=False), sa.Column("residual_resource_count", sa.Integer(), nullable=False), sa.Column("status", sa.String(32), nullable=False), sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "rehearsal_id", name="uq_purple_rehearsal_tenant_id"))
    for table in TABLES:
        _tenant_rls(table)


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f'DROP TABLE IF EXISTS "{table}"')


def _create(name: str, *columns: object) -> None:
    op.create_table(name, sa.Column("id", sa.String(64), primary_key=True), *columns, *_owned())


def _owned() -> tuple[sa.Column, ...]:
    return (sa.Column("tenant_id", sa.String(64), nullable=False), sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))


def _tenant_rls(table: str) -> None:
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
    op.execute(f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" USING (tenant_id = NULLIF(current_setting(\'redagent.tenant_id\', true), \'\')) WITH CHECK (tenant_id = NULLIF(current_setting(\'redagent.tenant_id\', true), \'\'))')

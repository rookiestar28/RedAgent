"""compat_101 persistent containment controls, phase truth, incidents, and hard quotas."""

from alembic import op
import sqlalchemy as sa


revision = "0008_r101_containment_quotas"
down_revision = "0007_r100_ephemeral_runners"
branch_labels = None
depends_on = None


TABLES = (
    "containment_controls", "containment_approvals", "containment_job_actions",
    "containment_phase_receipts", "containment_residual_risks", "containment_incidents",
    "quota_policies", "quota_usage", "quota_reservations", "quota_operations",
)


def upgrade() -> None:
    op.create_table(
        "containment_controls", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("stop_id", sa.String(64), nullable=False), sa.Column("scope_kind", sa.String(32), nullable=False),
        sa.Column("scope_id", sa.String(200)), sa.Column("control_mode", sa.String(32), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False), sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("reason_hash", sa.String(64), nullable=False), sa.Column("initiated_by_user_id", sa.String(64), nullable=False),
        sa.Column("approved_by_user_id", sa.String(64)), sa.Column("control_state", sa.String(32), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False), sa.Column("activated_at", sa.DateTime(timezone=True)),
        sa.Column("ack_deadline", sa.DateTime(timezone=True), nullable=False), sa.Column("recovered_at", sa.DateTime(timezone=True)),
        *_owned(), sa.CheckConstraint("initiated_by_user_id <> approved_by_user_id", name="ck_containment_control_sod"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_containment_controls_tenant_request"),
        sa.UniqueConstraint("tenant_id", "stop_id", name="uq_containment_controls_tenant_stop"),
    )
    op.create_table(
        "containment_approvals", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("control_id", sa.String(64), nullable=False), sa.Column("approval_id", sa.String(64), nullable=False),
        sa.Column("approver_user_id", sa.String(64), nullable=False), sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("approval_state", sa.String(32), nullable=False), sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        *_owned(), sa.ForeignKeyConstraint(["control_id"], ["containment_controls.id"]),
        sa.UniqueConstraint("tenant_id", "approval_id", name="uq_containment_approvals_tenant_approval"),
    )
    op.create_table(
        "containment_job_actions", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("control_id", sa.String(64), nullable=False), sa.Column("job_id", sa.String(64), nullable=False),
        sa.Column("runner_registration_id", sa.String(64)), sa.Column("action_state", sa.String(32), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)), sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("outcome", sa.String(64)), sa.Column("duration_ms", sa.Integer()),
        *_owned(), sa.ForeignKeyConstraint(["control_id"], ["containment_controls.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"]),
        sa.UniqueConstraint("tenant_id", "control_id", "job_id", name="uq_containment_actions_tenant_job"),
    )
    op.create_table(
        "containment_phase_receipts", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("action_id", sa.String(64), nullable=False), sa.Column("phase", sa.String(32), nullable=False),
        sa.Column("phase_state", sa.String(32), nullable=False), sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("receipt_hash", sa.String(64), nullable=False), sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["action_id"], ["containment_job_actions.id"]),
        sa.UniqueConstraint("tenant_id", "action_id", "phase", name="uq_containment_phases_tenant_action_phase"),
    )
    op.create_table(
        "containment_residual_risks", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("action_id", sa.String(64), nullable=False), sa.Column("risk_code", sa.String(100), nullable=False),
        sa.Column("risk_state", sa.String(32), nullable=False), sa.Column("details_hash", sa.String(64), nullable=False),
        sa.Column("dispositioned_by_user_id", sa.String(64)), sa.Column("dispositioned_at", sa.DateTime(timezone=True)),
        *_owned(), sa.ForeignKeyConstraint(["action_id"], ["containment_job_actions.id"]),
        sa.UniqueConstraint("tenant_id", "action_id", "risk_code", name="uq_containment_residual_tenant_risk"),
    )
    op.create_table(
        "containment_incidents", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("incident_id", sa.String(64), nullable=False), sa.Column("control_id", sa.String(64)),
        sa.Column("action_id", sa.String(64)), sa.Column("incident_kind", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False), sa.Column("incident_state", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False), sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True)), *_owned(),
        sa.ForeignKeyConstraint(["control_id"], ["containment_controls.id"]),
        sa.ForeignKeyConstraint(["action_id"], ["containment_job_actions.id"]),
        sa.UniqueConstraint("tenant_id", "incident_id", name="uq_containment_incidents_tenant_incident"),
    )
    op.create_table(
        "quota_policies", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("policy_id", sa.String(64), nullable=False), sa.Column("policy_revision", sa.Integer(), nullable=False),
        sa.Column("dimension", sa.String(32), nullable=False), sa.Column("extension_name", sa.String(64)),
        sa.Column("scope_kind", sa.String(32), nullable=False), sa.Column("scope_id", sa.String(200)),
        sa.Column("scope_key", sa.String(256), nullable=False),
        sa.Column("hard_limit", sa.BigInteger(), nullable=False), sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("active_from", sa.DateTime(timezone=True), nullable=False), sa.Column("active_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("policy_state", sa.String(32), nullable=False), *_owned(),
        sa.CheckConstraint("hard_limit > 0", name="ck_quota_policy_limit_positive"),
        sa.UniqueConstraint("tenant_id", "policy_id", "policy_revision", "dimension", "scope_key", name="uq_quota_policies_tenant_revision_dimension_scope"),
    )
    op.create_table(
        "quota_usage", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("policy_record_id", sa.String(64), nullable=False), sa.Column("scope_key", sa.String(256), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False), sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reserved_amount", sa.BigInteger(), nullable=False), sa.Column("consumed_amount", sa.BigInteger(), nullable=False),
        *_owned(), sa.ForeignKeyConstraint(["policy_record_id"], ["quota_policies.id"]),
        sa.UniqueConstraint("tenant_id", "policy_record_id", "window_start", "scope_key", name="uq_quota_usage_tenant_policy_window_scope"),
        sa.CheckConstraint("reserved_amount >= 0 AND consumed_amount >= 0", name="ck_quota_usage_nonnegative"),
    )
    op.create_table(
        "quota_reservations", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("reservation_id", sa.String(100), nullable=False), sa.Column("policy_record_id", sa.String(64), nullable=False),
        sa.Column("usage_id", sa.String(64), nullable=False), sa.Column("reserved_amount", sa.BigInteger(), nullable=False),
        sa.Column("consumed_amount", sa.BigInteger(), nullable=False), sa.Column("released_amount", sa.BigInteger(), nullable=False),
        sa.Column("reservation_state", sa.String(32), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        *_owned(), sa.ForeignKeyConstraint(["policy_record_id"], ["quota_policies.id"]),
        sa.ForeignKeyConstraint(["usage_id"], ["quota_usage.id"]),
        sa.UniqueConstraint("tenant_id", "reservation_id", name="uq_quota_reservations_tenant_reservation"),
        sa.CheckConstraint("reserved_amount > 0 AND consumed_amount >= 0 AND released_amount >= 0", name="ck_quota_reservation_amounts"),
        sa.CheckConstraint("consumed_amount + released_amount <= reserved_amount", name="ck_quota_reservation_balance"),
    )
    op.create_table(
        "quota_operations", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("operation_id", sa.String(100), nullable=False), sa.Column("policy_record_id", sa.String(64), nullable=False),
        sa.Column("reservation_record_id", sa.String(64)), sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("operation_kind", sa.String(32), nullable=False), sa.Column("amount", sa.BigInteger(), nullable=False),
        sa.Column("remaining_after", sa.BigInteger(), nullable=False), sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False), sa.Column("containment_control_id", sa.String(64)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["policy_record_id"], ["quota_policies.id"]),
        sa.ForeignKeyConstraint(["reservation_record_id"], ["quota_reservations.id"]),
        sa.ForeignKeyConstraint(["containment_control_id"], ["containment_controls.id"]),
        sa.UniqueConstraint("tenant_id", "operation_id", name="uq_quota_operations_tenant_operation"),
        sa.CheckConstraint("amount > 0 AND remaining_after >= 0", name="ck_quota_operation_amounts"),
    )
    for table in TABLES:
        _tenant_rls(table)


def downgrade() -> None:
    op.drop_table("quota_operations")
    # IMPORTANT: supports local pre-acceptance 0008 drafts that did not create this table.
    op.drop_table("quota_reservations", if_exists=True)
    op.drop_table("quota_usage")
    op.drop_table("quota_policies")
    op.drop_table("containment_incidents")
    op.drop_table("containment_residual_risks")
    op.drop_table("containment_phase_receipts")
    op.drop_table("containment_job_actions")
    op.drop_table("containment_approvals")
    op.drop_table("containment_controls")


def _owned() -> tuple[sa.Column, ...]:
    return (
        sa.Column("tenant_id", sa.String(64), nullable=False), sa.Column("version", sa.Integer(), nullable=False),
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

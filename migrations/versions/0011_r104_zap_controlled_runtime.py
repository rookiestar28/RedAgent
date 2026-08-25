"""compat_104 controlled ZAP profiles, plans, runs, gateway, alerts, stop, and cleanup."""

from alembic import op
import sqlalchemy as sa


revision = "0011_r104_zap_runtime"
down_revision = "0010_r103_safe_lab"
branch_labels = None
depends_on = None


TABLES = (
    "zap_profile_revisions", "zap_target_attestations", "zap_compiled_plans", "zap_runs", "zap_run_steps",
    "zap_gateway_decisions", "zap_normalized_alerts", "zap_cancellation_receipts",
    "zap_cleanup_receipts",
)


def upgrade() -> None:
    op.create_table(
        "zap_profile_revisions", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("profile_id", sa.String(100), nullable=False),
        sa.Column("profile_revision", sa.Integer(), nullable=False),
        sa.Column("image_version", sa.String(32), nullable=False),
        sa.Column("image_digest", sa.String(71), nullable=False),
        sa.Column("addon_inventory_sha256", sa.String(64), nullable=False),
        sa.Column("profile_sha256", sa.String(64), nullable=False),
        sa.Column("risk_class", sa.String(32), nullable=False),
        sa.Column("passive_rule_ids", sa.JSON(), nullable=False),
        sa.Column("active_rule_ids", sa.JSON(), nullable=False),
        sa.Column("request_limit", sa.Integer(), nullable=False),
        sa.Column("request_rate_per_second", sa.Integer(), nullable=False),
        sa.Column("concurrency_limit", sa.Integer(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("response_bytes_limit", sa.BigInteger(), nullable=False),
        sa.Column("profile_state", sa.String(32), nullable=False), *_owned(),
        sa.UniqueConstraint("tenant_id", "profile_id", "profile_revision", name="uq_zap_profile_tenant_revision"),
    )
    op.create_table(
        "zap_target_attestations", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("attestation_id", sa.String(100), nullable=False),
        sa.Column("target_id", sa.String(100), nullable=False),
        sa.Column("target_source_sha256", sa.String(64), nullable=False),
        sa.Column("target_image_id", sa.String(71), nullable=False),
        sa.Column("network_id", sa.String(100), nullable=False),
        sa.Column("container_name", sa.String(100), nullable=False),
        sa.Column("address_sha256", sa.String(64), nullable=False),
        sa.Column("endpoint", sa.String(200), nullable=False),
        sa.Column("allowed_paths", sa.JSON(), nullable=False),
        sa.Column("attestation_sha256", sa.String(64), nullable=False),
        sa.Column("non_production", sa.Boolean(), nullable=False),
        sa.Column("attestation_state", sa.String(32), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.UniqueConstraint("tenant_id", "attestation_id", name="uq_zap_target_attestation_tenant_id"),
        sa.UniqueConstraint("tenant_id", "target_id", "attestation_sha256", name="uq_zap_target_attestation_tenant_hash"),
    )
    op.create_table(
        "zap_compiled_plans", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("profile_record_id", sa.String(64), nullable=False),
        sa.Column("plan_id", sa.String(100), nullable=False),
        sa.Column("target_id", sa.String(100), nullable=False),
        sa.Column("target_attestation_sha256", sa.String(64), nullable=False),
        sa.Column("policy_decision_id", sa.String(100), nullable=False),
        sa.Column("roe_version_id", sa.String(64), nullable=False),
        sa.Column("plan_sha256", sa.String(64), nullable=False),
        sa.Column("scope_sha256", sa.String(64), nullable=False),
        sa.Column("compiled_plan", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["profile_record_id"], ["zap_profile_revisions.id"]),
        sa.UniqueConstraint("tenant_id", "plan_id", name="uq_zap_plan_tenant_plan"),
    )
    op.create_table(
        "zap_runs", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("plan_record_id", sa.String(64), nullable=False),
        sa.Column("run_id", sa.String(100), nullable=False),
        sa.Column("job_id", sa.String(100), nullable=False),
        sa.Column("runner_id", sa.String(100), nullable=False),
        sa.Column("run_state", sa.String(32), nullable=False),
        sa.Column("current_step", sa.Integer(), nullable=False),
        sa.Column("progress_percent", sa.Integer(), nullable=False),
        sa.Column("passive_queue_size", sa.Integer(), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)), *_owned(),
        sa.ForeignKeyConstraint(["plan_record_id"], ["zap_compiled_plans.id"]),
        sa.UniqueConstraint("tenant_id", "run_id", name="uq_zap_run_tenant_run"),
        sa.CheckConstraint("progress_percent >= 0 AND progress_percent <= 100", name="ck_zap_progress_percent"),
        sa.CheckConstraint("passive_queue_size >= 0", name="ck_zap_passive_queue_nonnegative"),
    )
    op.create_table(
        "zap_run_steps", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("run_record_id", sa.String(64), nullable=False),
        sa.Column("step_id", sa.String(100), nullable=False),
        sa.Column("step_type", sa.String(32), nullable=False),
        sa.Column("step_state", sa.String(32), nullable=False),
        sa.Column("progress_percent", sa.Integer(), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("response_bytes", sa.BigInteger(), nullable=False),
        sa.Column("receipt_sha256", sa.String(64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["run_record_id"], ["zap_runs.id"]),
        sa.UniqueConstraint("tenant_id", "run_record_id", "step_id", name="uq_zap_step_tenant_run_step"),
        sa.CheckConstraint("request_count >= 0 AND response_bytes >= 0", name="ck_zap_step_quota_nonnegative"),
    )
    op.create_table(
        "zap_gateway_decisions", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("run_record_id", sa.String(64), nullable=False),
        sa.Column("decision_id", sa.String(100), nullable=False),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column("path_sha256", sa.String(64), nullable=False),
        sa.Column("destination_sha256", sa.String(64), nullable=False),
        sa.Column("allowed", sa.Boolean(), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("response_bytes", sa.BigInteger(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["run_record_id"], ["zap_runs.id"]),
        sa.UniqueConstraint("tenant_id", "decision_id", name="uq_zap_gateway_tenant_decision"),
    )
    op.create_table(
        "zap_normalized_alerts", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("run_record_id", sa.String(64), nullable=False),
        sa.Column("alert_id", sa.String(100), nullable=False),
        sa.Column("rule_id", sa.String(32), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("confidence", sa.String(32), nullable=False),
        sa.Column("affected_resource", sa.String(200), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("evidence_instance_id", sa.String(100), nullable=False),
        sa.Column("source_sha256", sa.String(64), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["run_record_id"], ["zap_runs.id"]),
        sa.UniqueConstraint("tenant_id", "run_record_id", "fingerprint", name="uq_zap_alert_tenant_run_fingerprint"),
    )
    op.create_table(
        "zap_cancellation_receipts", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("run_record_id", sa.String(64), nullable=False),
        sa.Column("receipt_id", sa.String(100), nullable=False),
        sa.Column("native_stop_attempted", sa.Boolean(), nullable=False),
        sa.Column("native_stop_acknowledged", sa.Boolean(), nullable=False),
        sa.Column("lease_revoked", sa.Boolean(), nullable=False),
        sa.Column("evidence_finalized", sa.Boolean(), nullable=False),
        sa.Column("forced_termination", sa.Boolean(), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["run_record_id"], ["zap_runs.id"]),
        sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_zap_cancel_tenant_receipt"),
    )
    op.create_table(
        "zap_cleanup_receipts", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("run_record_id", sa.String(64), nullable=False),
        sa.Column("receipt_id", sa.String(100), nullable=False),
        sa.Column("container_count", sa.Integer(), nullable=False),
        sa.Column("network_count", sa.Integer(), nullable=False),
        sa.Column("home_count", sa.Integer(), nullable=False),
        sa.Column("key_count", sa.Integer(), nullable=False),
        sa.Column("credential_count", sa.Integer(), nullable=False),
        sa.Column("residual_resource_count", sa.Integer(), nullable=False),
        sa.Column("cleanup_complete", sa.Boolean(), nullable=False),
        sa.Column("inventory_sha256", sa.String(64), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["run_record_id"], ["zap_runs.id"]),
        sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_zap_cleanup_tenant_receipt"),
        sa.CheckConstraint(
            "container_count >= 0 AND network_count >= 0 AND home_count >= 0 AND key_count >= 0 "
            "AND credential_count >= 0 AND residual_resource_count >= 0",
            name="ck_zap_cleanup_counts_nonnegative",
        ),
    )
    for table in TABLES:
        _tenant_rls(table)


def downgrade() -> None:
    op.drop_table("zap_cleanup_receipts")
    op.drop_table("zap_cancellation_receipts")
    op.drop_table("zap_normalized_alerts")
    op.drop_table("zap_gateway_decisions")
    op.drop_table("zap_run_steps")
    op.drop_table("zap_runs")
    op.drop_table("zap_compiled_plans")
    op.drop_table("zap_target_attestations", if_exists=True)
    op.drop_table("zap_profile_revisions")


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

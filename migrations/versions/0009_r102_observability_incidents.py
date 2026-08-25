"""compat_102 durable telemetry delivery, incidents, alerts, and SLO truth."""

from alembic import op
import sqlalchemy as sa


revision = "0009_r102_observability_ir"
down_revision = "0008_r101_containment_quotas"
branch_labels = None
depends_on = None


TABLES = (
    "telemetry_export_operations", "telemetry_delivery_attempts", "telemetry_dead_letters",
    "security_incidents", "incident_timeline_events", "incident_actions",
    "slo_definitions", "slo_windows", "slo_evaluations",
    "alert_instances", "alert_notifications",
)


def upgrade() -> None:
    op.create_table(
        "telemetry_export_operations", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("operation_id", sa.String(100), nullable=False),
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("envelope_hash", sa.String(64), nullable=False),
        sa.Column("envelope", sa.JSON(), nullable=False),
        sa.Column("signal_kind", sa.String(16), nullable=False),
        sa.Column("priority", sa.String(16), nullable=False),
        sa.Column("export_state", sa.String(32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("claim_owner_id", sa.String(64)),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_reason_code", sa.String(100)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.CheckConstraint("attempt_count >= 0", name="ck_telemetry_exports_attempt_nonnegative"),
        sa.UniqueConstraint("tenant_id", "operation_id", name="uq_telemetry_exports_tenant_operation"),
    )
    op.create_table(
        "telemetry_delivery_attempts", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("export_operation_id", sa.String(64), nullable=False),
        sa.Column("attempt_id", sa.String(64), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("destination_alias", sa.String(64), nullable=False),
        sa.Column("attempt_state", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)), *_owned(),
        sa.ForeignKeyConstraint(["export_operation_id"], ["telemetry_export_operations.id"]),
        sa.CheckConstraint("attempt_number > 0", name="ck_telemetry_attempt_number_positive"),
        sa.UniqueConstraint(
            "tenant_id", "export_operation_id", "attempt_number",
            name="uq_telemetry_attempts_tenant_export_number",
        ),
        sa.UniqueConstraint("tenant_id", "attempt_id", name="uq_telemetry_attempts_tenant_attempt"),
    )
    op.create_table(
        "telemetry_dead_letters", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("export_operation_id", sa.String(64), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("replay_id", sa.String(64)),
        sa.Column("dead_lettered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("replayed_at", sa.DateTime(timezone=True)), *_owned(),
        sa.ForeignKeyConstraint(["export_operation_id"], ["telemetry_export_operations.id"]),
        sa.UniqueConstraint(
            "tenant_id", "export_operation_id", name="uq_telemetry_dead_letters_tenant_export",
        ),
    )
    op.create_table(
        "security_incidents", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("incident_id", sa.String(64), nullable=False),
        sa.Column("source_kind", sa.String(32), nullable=False),
        sa.Column("source_id", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("incident_state", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("opened_by_user_id", sa.String(64), nullable=False),
        sa.Column("assigned_to_user_id", sa.String(64)),
        sa.Column("acknowledged_by_user_id", sa.String(64)),
        sa.Column("contained_by_user_id", sa.String(64)),
        sa.Column("recovered_by_user_id", sa.String(64)),
        sa.Column("reviewed_by_user_id", sa.String(64)),
        sa.Column("evidence_preserved", sa.Boolean(), nullable=False),
        sa.Column("containment_verified", sa.Boolean(), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True)), *_owned(),
        sa.CheckConstraint("opened_by_user_id <> recovered_by_user_id", name="ck_security_incident_recovery_sod"),
        sa.UniqueConstraint("tenant_id", "incident_id", name="uq_security_incidents_tenant_incident"),
    )
    op.create_table(
        "incident_timeline_events", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("incident_record_id", sa.String(64), nullable=False),
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("actor_user_id", sa.String(64), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["incident_record_id"], ["security_incidents.id"]),
        sa.UniqueConstraint("tenant_id", "event_id", name="uq_incident_timeline_tenant_event"),
    )
    op.create_table(
        "incident_actions", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("incident_record_id", sa.String(64), nullable=False),
        sa.Column("action_id", sa.String(64), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor_user_id", sa.String(64), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("expected_version", sa.Integer(), nullable=False),
        sa.Column("result_version", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["incident_record_id"], ["security_incidents.id"]),
        sa.UniqueConstraint("tenant_id", "action_id", name="uq_incident_actions_tenant_action"),
    )
    op.create_table(
        "slo_definitions", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("objective_id", sa.String(64), nullable=False),
        sa.Column("objective_revision", sa.Integer(), nullable=False),
        sa.Column("metric_name", sa.String(64), nullable=False),
        sa.Column("comparison", sa.String(8), nullable=False),
        sa.Column("target_basis_points", sa.Integer()),
        sa.Column("threshold_millionths", sa.BigInteger()),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("minimum_samples", sa.Integer(), nullable=False),
        sa.Column("definition_state", sa.String(32), nullable=False), *_owned(),
        sa.UniqueConstraint(
            "tenant_id", "objective_id", "objective_revision",
            name="uq_slo_definitions_tenant_objective_revision",
        ),
    )
    op.create_table(
        "slo_windows", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("definition_id", sa.String(64), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("total_count", sa.BigInteger(), nullable=False),
        sa.Column("bad_count", sa.BigInteger(), nullable=False),
        sa.Column("missing_count", sa.BigInteger(), nullable=False),
        sa.Column("source_hash", sa.String(64), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["definition_id"], ["slo_definitions.id"]),
        sa.UniqueConstraint(
            "tenant_id", "definition_id", "window_start", "window_end",
            name="uq_slo_windows_tenant_objective_window",
        ),
    )
    op.create_table(
        "slo_evaluations", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("window_id", sa.String(64), nullable=False),
        sa.Column("evaluation_state", sa.String(32), nullable=False),
        sa.Column("observed_millionths", sa.BigInteger()),
        sa.Column("burn_numerator", sa.BigInteger()),
        sa.Column("burn_denominator", sa.BigInteger()),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["window_id"], ["slo_windows.id"]),
        sa.UniqueConstraint("tenant_id", "window_id", name="uq_slo_evaluations_tenant_window"),
    )
    op.create_table(
        "alert_instances", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("alert_state", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("evaluation_id", sa.String(64)),
        sa.Column("incident_record_id", sa.String(64)),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["evaluation_id"], ["slo_evaluations.id"]),
        sa.ForeignKeyConstraint(["incident_record_id"], ["security_incidents.id"]),
        sa.UniqueConstraint(
            "tenant_id", "rule_id", "fingerprint",
            name="uq_alert_instances_tenant_rule_fingerprint",
        ),
    )
    op.create_table(
        "alert_notifications", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("alert_instance_id", sa.String(64), nullable=False),
        sa.Column("attempt_id", sa.String(64), nullable=False),
        sa.Column("destination_alias", sa.String(64), nullable=False),
        sa.Column("notification_state", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["alert_instance_id"], ["alert_instances.id"]),
        sa.UniqueConstraint("tenant_id", "attempt_id", name="uq_alert_notifications_tenant_attempt"),
    )
    for table in TABLES:
        _tenant_rls(table)


def downgrade() -> None:
    op.drop_table("alert_notifications")
    op.drop_table("alert_instances")
    op.drop_table("slo_evaluations")
    op.drop_table("slo_windows")
    op.drop_table("slo_definitions")
    op.drop_table("incident_actions")
    op.drop_table("incident_timeline_events")
    op.drop_table("security_incidents")
    op.drop_table("telemetry_dead_letters")
    op.drop_table("telemetry_delivery_attempts")
    op.drop_table("telemetry_export_operations")


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

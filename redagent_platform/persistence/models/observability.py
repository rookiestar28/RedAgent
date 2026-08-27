"""SQLAlchemy table registrations for the observability domain."""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Table,
    UniqueConstraint,
)

from ._base import _owned_columns, metadata


Table(
    "telemetry_export_operations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("operation_id", String(100), nullable=False),
    Column("event_id", String(64), nullable=False),
    Column("envelope_hash", String(64), nullable=False),
    Column("envelope", JSON, nullable=False),
    Column("signal_kind", String(16), nullable=False),
    Column("priority", String(16), nullable=False),
    Column("export_state", String(32), nullable=False),
    Column("attempt_count", Integer, nullable=False),
    Column("next_attempt_at", DateTime(timezone=True)),
    Column("claim_owner_id", String(64)),
    Column("claim_expires_at", DateTime(timezone=True)),
    Column("last_reason_code", String(100)),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    CheckConstraint("attempt_count >= 0", name="ck_telemetry_exports_attempt_nonnegative"),
    UniqueConstraint("tenant_id", "operation_id", name="uq_telemetry_exports_tenant_operation"),
)

Table(
    "telemetry_delivery_attempts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("export_operation_id", String(64), ForeignKey("telemetry_export_operations.id"), nullable=False),
    Column("attempt_id", String(64), nullable=False),
    Column("attempt_number", Integer, nullable=False),
    Column("destination_alias", String(64), nullable=False),
    Column("attempt_state", String(32), nullable=False),
    Column("reason_code", String(100), nullable=False),
    Column("started_at", DateTime(timezone=True), nullable=False),
    Column("completed_at", DateTime(timezone=True)),
    *_owned_columns(),
    UniqueConstraint(
        "tenant_id", "export_operation_id", "attempt_number", name="uq_telemetry_attempts_tenant_export_number"
    ),
    UniqueConstraint("tenant_id", "attempt_id", name="uq_telemetry_attempts_tenant_attempt"),
)

Table(
    "telemetry_dead_letters",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("export_operation_id", String(64), ForeignKey("telemetry_export_operations.id"), nullable=False),
    Column("reason_code", String(100), nullable=False),
    Column("payload_hash", String(64), nullable=False),
    Column("replay_id", String(64)),
    Column("dead_lettered_at", DateTime(timezone=True), nullable=False),
    Column("replayed_at", DateTime(timezone=True)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "export_operation_id", name="uq_telemetry_dead_letters_tenant_export"),
)

Table(
    "security_incidents",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("incident_id", String(64), nullable=False),
    Column("source_kind", String(32), nullable=False),
    Column("source_id", String(64), nullable=False),
    Column("severity", String(16), nullable=False),
    Column("incident_state", String(32), nullable=False),
    Column("reason_code", String(100), nullable=False),
    Column("opened_by_user_id", String(64), nullable=False),
    Column("assigned_to_user_id", String(64)),
    Column("acknowledged_by_user_id", String(64)),
    Column("contained_by_user_id", String(64)),
    Column("recovered_by_user_id", String(64)),
    Column("reviewed_by_user_id", String(64)),
    Column("evidence_preserved", Boolean, nullable=False),
    Column("containment_verified", Boolean, nullable=False),
    Column("opened_at", DateTime(timezone=True), nullable=False),
    Column("closed_at", DateTime(timezone=True)),
    *_owned_columns(),
    CheckConstraint("opened_by_user_id <> recovered_by_user_id", name="ck_security_incident_recovery_sod"),
    UniqueConstraint("tenant_id", "incident_id", name="uq_security_incidents_tenant_incident"),
)

Table(
    "incident_timeline_events",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("incident_record_id", String(64), ForeignKey("security_incidents.id"), nullable=False),
    Column("event_id", String(64), nullable=False),
    Column("event_type", String(32), nullable=False),
    Column("actor_user_id", String(64), nullable=False),
    Column("reason_code", String(100), nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "event_id", name="uq_incident_timeline_tenant_event"),
)

Table(
    "incident_actions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("incident_record_id", String(64), ForeignKey("security_incidents.id"), nullable=False),
    Column("action_id", String(64), nullable=False),
    Column("action", String(32), nullable=False),
    Column("actor_user_id", String(64), nullable=False),
    Column("request_hash", String(64), nullable=False),
    Column("expected_version", Integer, nullable=False),
    Column("result_version", Integer, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "action_id", name="uq_incident_actions_tenant_action"),
)

Table(
    "slo_definitions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("objective_id", String(64), nullable=False),
    Column("objective_revision", Integer, nullable=False),
    Column("metric_name", String(64), nullable=False),
    Column("comparison", String(8), nullable=False),
    Column("target_basis_points", Integer),
    Column("threshold_millionths", BigInteger),
    Column("window_seconds", Integer, nullable=False),
    Column("minimum_samples", Integer, nullable=False),
    Column("definition_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint(
        "tenant_id", "objective_id", "objective_revision", name="uq_slo_definitions_tenant_objective_revision"
    ),
)

Table(
    "slo_windows",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("definition_id", String(64), ForeignKey("slo_definitions.id"), nullable=False),
    Column("window_start", DateTime(timezone=True), nullable=False),
    Column("window_end", DateTime(timezone=True), nullable=False),
    Column("total_count", BigInteger, nullable=False),
    Column("bad_count", BigInteger, nullable=False),
    Column("missing_count", BigInteger, nullable=False),
    Column("source_hash", String(64), nullable=False),
    *_owned_columns(),
    UniqueConstraint(
        "tenant_id", "definition_id", "window_start", "window_end", name="uq_slo_windows_tenant_objective_window"
    ),
)

Table(
    "slo_evaluations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("window_id", String(64), ForeignKey("slo_windows.id"), nullable=False),
    Column("evaluation_state", String(32), nullable=False),
    Column("observed_millionths", BigInteger),
    Column("burn_numerator", BigInteger),
    Column("burn_denominator", BigInteger),
    Column("reason_code", String(100), nullable=False),
    Column("evaluated_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "window_id", name="uq_slo_evaluations_tenant_window"),
)

Table(
    "alert_instances",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("rule_id", String(64), nullable=False),
    Column("fingerprint", String(64), nullable=False),
    Column("alert_state", String(32), nullable=False),
    Column("severity", String(16), nullable=False),
    Column("evaluation_id", String(64), ForeignKey("slo_evaluations.id")),
    Column("incident_record_id", String(64), ForeignKey("security_incidents.id")),
    Column("first_seen_at", DateTime(timezone=True), nullable=False),
    Column("last_seen_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "rule_id", "fingerprint", name="uq_alert_instances_tenant_rule_fingerprint"),
)

Table(
    "alert_notifications",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("alert_instance_id", String(64), ForeignKey("alert_instances.id"), nullable=False),
    Column("attempt_id", String(64), nullable=False),
    Column("destination_alias", String(64), nullable=False),
    Column("notification_state", String(32), nullable=False),
    Column("reason_code", String(100), nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "attempt_id", name="uq_alert_notifications_tenant_attempt"),
)

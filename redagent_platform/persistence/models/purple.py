"""SQLAlchemy table registrations for the purple domain."""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    UniqueConstraint,
)

from ._base import _owned_columns, metadata


Table(
    "purple_adapter_artifacts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("adapter_id", String(100), nullable=False),
    Column("adapter_sha256", String(64), nullable=False),
    Column("owned", Boolean, nullable=False),
    Column("external_execution_allowed", Boolean, nullable=False),
    Column("artifact_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "adapter_id", "adapter_sha256"),
)

Table(
    "purple_abilities",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("ability_id", String(100), nullable=False),
    Column("ability_sha256", String(64), nullable=False),
    Column("adapter_record_id", String(64), ForeignKey("purple_adapter_artifacts.id"), nullable=False),
    Column("attack_version", String(64), nullable=False),
    Column("attack_technique_id", String(32), nullable=False),
    Column("platform", String(100), nullable=False),
    Column("content_sha256", String(64), nullable=False),
    Column("network_allowed", Boolean, nullable=False),
    Column("subprocess_allowed", Boolean, nullable=False),
    Column("ability_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "ability_id", "ability_sha256"),
)

Table(
    "purple_ability_phases",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("ability_record_id", String(64), ForeignKey("purple_abilities.id"), nullable=False),
    Column("phase_order", Integer, nullable=False),
    Column("phase_kind", String(32), nullable=False),
    Column("operation_id", String(100), nullable=False),
    Column("operation_sha256", String(64), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "ability_record_id", "phase_order"),
)

Table(
    "purple_detection_expectations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("ability_record_id", String(64), ForeignKey("purple_abilities.id"), nullable=False),
    Column("strategy_id", String(100), nullable=False),
    Column("analytic_id", String(100), nullable=False),
    Column("event_schema", String(100), nullable=False),
    Column("collector_id", String(100), nullable=False),
    Column("expectation_sha256", String(64), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "ability_record_id", "analytic_id"),
)

Table(
    "purple_lab_bindings",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("binding_id", String(100), nullable=False),
    Column("target_id", String(100), nullable=False),
    Column("runner_id", String(100), nullable=False),
    Column("snapshot_sha256", String(64), nullable=False),
    Column("telemetry_collector_id", String(100), nullable=False),
    Column("disposable", Boolean, nullable=False),
    Column("production", Boolean, nullable=False),
    Column("egress_allowed", Boolean, nullable=False),
    Column("binding_state", String(32), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "binding_id"),
)

Table(
    "purple_approvals",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("approval_id", String(100), nullable=False),
    Column("ability_record_id", String(64), ForeignKey("purple_abilities.id"), nullable=False),
    Column("lab_binding_record_id", String(64), ForeignKey("purple_lab_bindings.id"), nullable=False),
    Column("ability_sha256", String(64), nullable=False),
    Column("adapter_sha256", String(64), nullable=False),
    Column("lab_snapshot_sha256", String(64), nullable=False),
    Column("requester_id", String(64), nullable=False),
    Column("approver_id", String(64), nullable=False),
    Column("executor_id", String(64), nullable=False),
    Column("approval_state", String(32), nullable=False),
    Column("approved_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "approval_id"),
)

Table(
    "purple_execution_plans",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("plan_id", String(100), nullable=False),
    Column("ability_record_id", String(64), ForeignKey("purple_abilities.id"), nullable=False),
    Column("lab_binding_record_id", String(64), ForeignKey("purple_lab_bindings.id"), nullable=False),
    Column("approval_record_id", String(64), ForeignKey("purple_approvals.id"), nullable=False),
    Column("policy_decision_id", String(100), nullable=False),
    Column("roe_revision", String(100), nullable=False),
    Column("reservation_id", String(100), nullable=False),
    Column("lease_id", String(100), nullable=False),
    Column("kill_switch_id", String(100), nullable=False),
    Column("quota_id", String(100), nullable=False),
    Column("plan_sha256", String(64), nullable=False),
    Column("plan_state", String(32), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "plan_id"),
)

Table(
    "purple_runs",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_id", String(100), nullable=False),
    Column("plan_record_id", String(64), ForeignKey("purple_execution_plans.id"), nullable=False),
    Column("job_id", String(100), nullable=False),
    Column("runner_id", String(100), nullable=False),
    Column("run_state", String(32), nullable=False),
    Column("dispatch_blocked", Boolean, nullable=False),
    Column("detection_observed", Boolean, nullable=False),
    Column("cleanup_complete", Boolean, nullable=False),
    Column("teardown_verified", Boolean, nullable=False),
    Column("failure_code", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_id"),
)

Table(
    "purple_snapshots",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("purple_runs.id"), nullable=False),
    Column("snapshot_kind", String(32), nullable=False),
    Column("entry_count", Integer, nullable=False),
    Column("inventory_sha256", String(64), nullable=False),
    Column("captured_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_record_id", "snapshot_kind"),
)

Table(
    "purple_action_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("purple_runs.id"), nullable=False),
    Column("phase_kind", String(32), nullable=False),
    Column("operation_id", String(100), nullable=False),
    Column("artifact_sha256", String(64), nullable=False),
    Column("network_contact_count", Integer, nullable=False),
    Column("subprocess_count", Integer, nullable=False),
    Column("privilege_use_count", Integer, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_record_id", "phase_kind"),
)

Table(
    "purple_telemetry_events",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("purple_runs.id"), nullable=False),
    Column("collector_id", String(100), nullable=False),
    Column("event_schema", String(100), nullable=False),
    Column("analytic_id", String(100), nullable=False),
    Column("event_sha256", String(64), nullable=False),
    Column("integrity_verified", Boolean, nullable=False),
    Column("correlated", Boolean, nullable=False),
    Column("observed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_record_id", "event_sha256"),
)

Table(
    "purple_cleanup_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("purple_runs.id"), nullable=False),
    Column("receipt_id", String(100), nullable=False),
    Column("marker_removed", Boolean, nullable=False),
    Column("residual_resource_count", Integer, nullable=False),
    Column("after_inventory_sha256", String(64), nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "receipt_id"),
)

Table(
    "purple_teardown_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("purple_runs.id"), nullable=False),
    Column("receipt_id", String(100), nullable=False),
    Column("lease_revoked", Boolean, nullable=False),
    Column("dispatch_blocked", Boolean, nullable=False),
    Column("kill_acknowledged", Boolean, nullable=False),
    Column("residual_resource_count", Integer, nullable=False),
    Column("teardown_verified", Boolean, nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "receipt_id"),
)

Table(
    "purple_rehearsal_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("rehearsal_id", String(100), nullable=False),
    Column("ability_sha256", String(64), nullable=False),
    Column("plan_sha256", String(64), nullable=False),
    Column("telemetry_event_sha256", String(64), nullable=False),
    Column("cleanup_sha256", String(64), nullable=False),
    Column("external_contact_count", Integer, nullable=False),
    Column("residual_resource_count", Integer, nullable=False),
    Column("status", String(32), nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "rehearsal_id"),
)

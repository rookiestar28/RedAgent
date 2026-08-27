"""SQLAlchemy table registrations for the containment domain."""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
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
    "containment_controls",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("stop_id", String(64), nullable=False),
    Column("scope_kind", String(32), nullable=False),
    Column("scope_id", String(200)),
    Column("control_mode", String(32), nullable=False),
    Column("request_hash", String(64), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("reason_hash", String(64), nullable=False),
    Column("initiated_by_user_id", String(64), nullable=False),
    Column("approved_by_user_id", String(64)),
    Column("control_state", String(32), nullable=False),
    Column("requested_at", DateTime(timezone=True), nullable=False),
    Column("activated_at", DateTime(timezone=True)),
    Column("ack_deadline", DateTime(timezone=True), nullable=False),
    Column("recovered_at", DateTime(timezone=True)),
    *_owned_columns(),
    CheckConstraint("initiated_by_user_id <> approved_by_user_id", name="ck_containment_control_sod"),
    UniqueConstraint("tenant_id", "idempotency_key", name="uq_containment_controls_tenant_request"),
    UniqueConstraint("tenant_id", "stop_id", name="uq_containment_controls_tenant_stop"),
)

Table(
    "containment_approvals",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("control_id", String(64), ForeignKey("containment_controls.id"), nullable=False),
    Column("approval_id", String(64), nullable=False),
    Column("approver_user_id", String(64), nullable=False),
    Column("request_hash", String(64), nullable=False),
    Column("approval_state", String(32), nullable=False),
    Column("approved_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "approval_id", name="uq_containment_approvals_tenant_approval"),
)

Table(
    "containment_job_actions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("control_id", String(64), ForeignKey("containment_controls.id"), nullable=False),
    Column("job_id", String(64), ForeignKey("jobs.id"), nullable=False),
    Column("runner_registration_id", String(64)),
    Column("action_state", String(32), nullable=False),
    Column("acknowledged_at", DateTime(timezone=True)),
    Column("completed_at", DateTime(timezone=True)),
    Column("outcome", String(64)),
    Column("duration_ms", Integer),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "control_id", "job_id", name="uq_containment_actions_tenant_job"),
)

Table(
    "containment_phase_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("action_id", String(64), ForeignKey("containment_job_actions.id"), nullable=False),
    Column("phase", String(32), nullable=False),
    Column("phase_state", String(32), nullable=False),
    Column("reason_code", String(100), nullable=False),
    Column("receipt_hash", String(64), nullable=False),
    Column("duration_ms", Integer, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "action_id", "phase", name="uq_containment_phases_tenant_action_phase"),
)

Table(
    "containment_residual_risks",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("action_id", String(64), ForeignKey("containment_job_actions.id"), nullable=False),
    Column("risk_code", String(100), nullable=False),
    Column("risk_state", String(32), nullable=False),
    Column("details_hash", String(64), nullable=False),
    Column("dispositioned_by_user_id", String(64)),
    Column("dispositioned_at", DateTime(timezone=True)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "action_id", "risk_code", name="uq_containment_residual_tenant_risk"),
)

Table(
    "containment_incidents",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("incident_id", String(64), nullable=False),
    Column("control_id", String(64), ForeignKey("containment_controls.id")),
    Column("action_id", String(64), ForeignKey("containment_job_actions.id")),
    Column("incident_kind", String(64), nullable=False),
    Column("severity", String(16), nullable=False),
    Column("incident_state", String(32), nullable=False),
    Column("reason_code", String(100), nullable=False),
    Column("opened_at", DateTime(timezone=True), nullable=False),
    Column("resolved_at", DateTime(timezone=True)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "incident_id", name="uq_containment_incidents_tenant_incident"),
)

Table(
    "quota_policies",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("policy_id", String(64), nullable=False),
    Column("policy_revision", Integer, nullable=False),
    Column("dimension", String(32), nullable=False),
    Column("extension_name", String(64)),
    Column("scope_kind", String(32), nullable=False),
    Column("scope_id", String(200)),
    Column("scope_key", String(256), nullable=False),
    Column("hard_limit", BigInteger, nullable=False),
    Column("window_seconds", Integer, nullable=False),
    Column("active_from", DateTime(timezone=True), nullable=False),
    Column("active_until", DateTime(timezone=True), nullable=False),
    Column("policy_state", String(32), nullable=False),
    *_owned_columns(),
    CheckConstraint("hard_limit > 0", name="ck_quota_policy_limit_positive"),
    UniqueConstraint(
        "tenant_id",
        "policy_id",
        "policy_revision",
        "dimension",
        "scope_key",
        name="uq_quota_policies_tenant_revision_dimension_scope",
    ),
)

Table(
    "quota_usage",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("policy_record_id", String(64), ForeignKey("quota_policies.id"), nullable=False),
    Column("scope_key", String(256), nullable=False),
    Column("window_start", DateTime(timezone=True), nullable=False),
    Column("window_end", DateTime(timezone=True), nullable=False),
    Column("reserved_amount", BigInteger, nullable=False),
    Column("consumed_amount", BigInteger, nullable=False),
    *_owned_columns(),
    CheckConstraint("reserved_amount >= 0 AND consumed_amount >= 0", name="ck_quota_usage_nonnegative"),
    UniqueConstraint(
        "tenant_id", "policy_record_id", "window_start", "scope_key", name="uq_quota_usage_tenant_policy_window_scope"
    ),
)

Table(
    "quota_reservations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("reservation_id", String(100), nullable=False),
    Column("policy_record_id", String(64), ForeignKey("quota_policies.id"), nullable=False),
    Column("usage_id", String(64), ForeignKey("quota_usage.id"), nullable=False),
    Column("reserved_amount", BigInteger, nullable=False),
    Column("consumed_amount", BigInteger, nullable=False),
    Column("released_amount", BigInteger, nullable=False),
    Column("reservation_state", String(32), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "reservation_id", name="uq_quota_reservations_tenant_reservation"),
)

Table(
    "quota_operations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("operation_id", String(100), nullable=False),
    Column("policy_record_id", String(64), ForeignKey("quota_policies.id"), nullable=False),
    Column("reservation_record_id", String(64), ForeignKey("quota_reservations.id")),
    Column("request_hash", String(64), nullable=False),
    Column("operation_kind", String(32), nullable=False),
    Column("amount", BigInteger, nullable=False),
    Column("remaining_after", BigInteger, nullable=False),
    Column("decision", String(32), nullable=False),
    Column("reason_code", String(100), nullable=False),
    Column("containment_control_id", String(64), ForeignKey("containment_controls.id")),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    CheckConstraint("amount > 0 AND remaining_after >= 0", name="ck_quota_operation_amounts"),
    UniqueConstraint("tenant_id", "operation_id", name="uq_quota_operations_tenant_operation"),
)

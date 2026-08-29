"""Relational metadata for durable, authority-bound campaign DAG execution."""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKeyConstraint,
    Integer,
    JSON,
    String,
    Table,
    UniqueConstraint,
)

from ._base import _owned_columns, metadata


Table(
    "campaign_execution_runs",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("execution_id", String(100), nullable=False),
    Column("principal_id", String(100), nullable=False),
    Column("campaign_id", String(64), nullable=False),
    Column("admission_receipt_id", String(64), nullable=False),
    Column("reservation_id", String(64), nullable=False),
    Column("workflow_id", String(100), nullable=False),
    Column("workflow_run_id", String(100)),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_sha256", String(64), nullable=False),
    Column("input_sha256", String(64), nullable=False),
    Column("input_payload", JSON, nullable=False),
    Column("signed_authority_sha256", String(64), nullable=False),
    Column("authority_sha256", String(64), nullable=False),
    Column("domain_sha256", String(64), nullable=False),
    Column("plan_sha256", String(64), nullable=False),
    Column("certificate_sha256", String(64), nullable=False),
    Column("admission_receipt_sha256", String(64), nullable=False),
    Column("reserved_budget_sha256", String(64), nullable=False),
    Column("lifecycle_epoch", Integer, nullable=False),
    Column("policy_revocation_epoch", Integer, nullable=False),
    Column("roe_revocation_epoch", Integer, nullable=False),
    Column("kill_switch_epoch", Integer, nullable=False),
    Column("run_state", String(32), nullable=False),
    Column("transition_count", Integer, nullable=False, default=0),
    Column("max_transitions", Integer, nullable=False),
    Column("rate_window_started_at", DateTime(timezone=True)),
    Column("rate_claimed_requests", Integer, nullable=False, default=0),
    Column("active_concurrency", Integer, nullable=False, default=0),
    Column("stop_requested", Boolean, nullable=False, default=False),
    Column("terminal_reason", String(100)),
    Column("started_at", DateTime(timezone=True)),
    Column("completed_at", DateTime(timezone=True)),
    *_owned_columns(),
    ForeignKeyConstraint(
        ("tenant_id", "campaign_id"),
        ("campaigns.tenant_id", "campaigns.id"),
        name="fk_campaign_execution_run_tenant_campaign",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "admission_receipt_id", "campaign_id"),
        (
            "plan_admission_receipts.tenant_id",
            "plan_admission_receipts.id",
            "plan_admission_receipts.campaign_id",
        ),
        name="fk_campaign_execution_run_tenant_admission_campaign",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "reservation_id", "campaign_id"),
        (
            "campaign_budget_reservations.tenant_id",
            "campaign_budget_reservations.id",
            "campaign_budget_reservations.campaign_id",
        ),
        name="fk_campaign_execution_run_tenant_reservation_campaign",
    ),
    UniqueConstraint("tenant_id", "id", "campaign_id", name="uq_campaign_execution_run_identity"),
    UniqueConstraint("tenant_id", "execution_id", name="uq_campaign_execution_run_execution"),
    UniqueConstraint("tenant_id", "workflow_id", name="uq_campaign_execution_run_workflow"),
    UniqueConstraint("tenant_id", "campaign_id", "plan_sha256", name="uq_campaign_execution_run_plan"),
    UniqueConstraint(
        "tenant_id", "campaign_id", "idempotency_key", name="uq_campaign_execution_run_idempotency"
    ),
    CheckConstraint(
        "run_state IN ('start_pending','running','stopping','reconciliation_required',"
        "'completed','contained','manual_review_required','failed_before_io','failed')",
        name="campaign_execution_run_state_closed",
    ),
    CheckConstraint(
        "transition_count BETWEEN 0 AND 2147483647 AND max_transitions BETWEEN 1 AND 2147483647",
        name="campaign_execution_run_transition_budget_bounded",
    ),
    CheckConstraint(
        "rate_claimed_requests BETWEEN 0 AND 2147483647 AND active_concurrency BETWEEN 0 AND 2147483647",
        name="campaign_execution_run_counters_bounded",
    ),
    CheckConstraint(
        "lifecycle_epoch BETWEEN 0 AND 2147483647 AND "
        "policy_revocation_epoch BETWEEN 0 AND 2147483647 AND "
        "roe_revocation_epoch BETWEEN 0 AND 2147483647 AND "
        "kill_switch_epoch BETWEEN 0 AND 2147483647",
        name="campaign_execution_run_epochs_bounded",
    ),
)


Table(
    "campaign_execution_nodes",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("execution_run_id", String(64), nullable=False),
    Column("campaign_id", String(64), nullable=False),
    Column("node_id", String(100), nullable=False),
    Column("node_order", Integer, nullable=False),
    Column("operator_id", String(100), nullable=False),
    Column("capability_id", String(100), nullable=False),
    Column("capability_revision", String(100), nullable=False),
    Column("target_id", String(100), nullable=False),
    Column("environment", String(100), nullable=False),
    Column("arguments_sha256", String(64), nullable=False),
    Column("incoming_edges_sha256", String(64), nullable=False),
    Column("join_sha256", String(64), nullable=False),
    Column("node_sha256", String(64), nullable=False),
    Column("node_state", String(32), nullable=False),
    *_owned_columns(),
    ForeignKeyConstraint(
        ("tenant_id", "execution_run_id", "campaign_id"),
        (
            "campaign_execution_runs.tenant_id",
            "campaign_execution_runs.id",
            "campaign_execution_runs.campaign_id",
        ),
        name="fk_campaign_execution_node_tenant_run_campaign",
    ),
    UniqueConstraint(
        "tenant_id", "execution_run_id", "node_id", name="uq_campaign_execution_node_stable"
    ),
    UniqueConstraint(
        "tenant_id", "execution_run_id", "node_order", name="uq_campaign_execution_node_order"
    ),
    CheckConstraint("node_order BETWEEN 0 AND 2147483647", name="campaign_execution_node_order_bounded"),
    CheckConstraint(
        "node_state IN ('pending','ready','reserved','claimed','dispatching',"
        "'reconciliation_required','not_applied','confirmed','skipped','contained',"
        "'manual_review_required','failed')",
        name="campaign_execution_node_state_closed",
    ),
)


Table(
    "campaign_execution_authority_observations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("execution_run_id", String(64), nullable=False),
    Column("campaign_id", String(64), nullable=False),
    Column("observation_sequence", Integer, nullable=False),
    Column("authority_sha256", String(64), nullable=False),
    Column("lifecycle_epoch", Integer, nullable=False),
    Column("policy_revocation_epoch", Integer, nullable=False),
    Column("roe_revocation_epoch", Integer, nullable=False),
    Column("kill_switch_epoch", Integer, nullable=False),
    Column("lifecycle_state", String(32), nullable=False),
    Column("lifecycle_sha256", String(64), nullable=False),
    Column("lifecycle_payload", JSON, nullable=False),
    Column("observed_at", DateTime(timezone=True), nullable=False),
    Column("valid_until", DateTime(timezone=True)),
    Column("revoked_at", DateTime(timezone=True)),
    Column("reason_code", String(100)),
    *_owned_columns(),
    ForeignKeyConstraint(
        ("tenant_id", "execution_run_id", "campaign_id"),
        (
            "campaign_execution_runs.tenant_id",
            "campaign_execution_runs.id",
            "campaign_execution_runs.campaign_id",
        ),
        name="fk_campaign_execution_observation_tenant_run_campaign",
    ),
    UniqueConstraint(
        "tenant_id",
        "execution_run_id",
        "observation_sequence",
        name="uq_campaign_execution_authority_observation_sequence",
    ),
    CheckConstraint(
        "observation_sequence BETWEEN 1 AND 2147483647",
        name="campaign_execution_authority_observation_sequence_bounded",
    ),
    CheckConstraint(
        "lifecycle_epoch BETWEEN 0 AND 2147483647 AND "
        "policy_revocation_epoch BETWEEN 0 AND 2147483647 AND "
        "roe_revocation_epoch BETWEEN 0 AND 2147483647 AND "
        "kill_switch_epoch BETWEEN 0 AND 2147483647",
        name="campaign_execution_authority_observation_epochs_bounded",
    ),
    CheckConstraint(
        "lifecycle_state IN ('active','suspended','revoked','expired')",
        name="campaign_execution_authority_observation_state_closed",
    ),
)

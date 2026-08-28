"""Relational metadata for atomic campaign plan admission and budget accounting."""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKeyConstraint,
    JSON,
    String,
    Table,
    UniqueConstraint,
)

from ._base import _owned_columns, metadata


_VECTOR_FIELDS = (
    "duration_seconds",
    "requests",
    "rate_per_minute",
    "concurrency",
    "risk_micropoints",
    "cost_microunits",
    "evidence_bytes",
    "data_bytes",
)


def _vector_columns() -> tuple[Column, ...]:
    return tuple(Column(name, BigInteger, nullable=False) for name in _VECTOR_FIELDS)


Table(
    "campaign_budget_ledgers",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("campaign_id", String(64), nullable=False),
    Column("envelope_sha256", String(64), nullable=False),
    *_vector_columns(),
    *_owned_columns(),
    ForeignKeyConstraint(
        ("tenant_id", "campaign_id"),
        ("campaigns.tenant_id", "campaigns.id"),
        name="fk_campaign_budget_ledger_tenant_campaign",
    ),
    UniqueConstraint("tenant_id", "id", name="uq_campaign_budget_ledger_tenant_identity"),
    UniqueConstraint("tenant_id", "campaign_id", name="uq_campaign_budget_ledger_tenant_campaign"),
    CheckConstraint(
        " AND ".join(f"{name} BETWEEN 0 AND 1000000000000000000" for name in _VECTOR_FIELDS),
        name="campaign_budget_vector_non_negative",
    ),
)

Table(
    "campaign_budget_reservations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("ledger_id", String(64), nullable=False),
    Column("campaign_id", String(64), nullable=False),
    Column("plan_sha256", String(64), nullable=False),
    Column("request_sha256", String(64), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("reservation_state", String(32), nullable=False),
    Column("lease_expires_at", DateTime(timezone=True), nullable=False),
    Column("effect_started", Boolean, nullable=False, default=False),
    Column("reconciliation_code", String(100)),
    *_vector_columns(),
    *_owned_columns(),
    ForeignKeyConstraint(
        ("tenant_id", "campaign_id"),
        ("campaigns.tenant_id", "campaigns.id"),
        name="fk_campaign_budget_reservation_tenant_campaign",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "ledger_id"),
        ("campaign_budget_ledgers.tenant_id", "campaign_budget_ledgers.id"),
        name="fk_campaign_budget_reservation_tenant_ledger",
    ),
    UniqueConstraint("tenant_id", "id", name="uq_campaign_budget_reservation_tenant_identity"),
    UniqueConstraint("tenant_id", "campaign_id", "plan_sha256", name="uq_campaign_budget_reservation_plan"),
    UniqueConstraint("tenant_id", "campaign_id", "idempotency_key", name="uq_campaign_budget_reservation_idempotency"),
    CheckConstraint(
        "reservation_state IN ('reserved','held','consumed','released','expired')",
        name="campaign_budget_reservation_state_closed",
    ),
    CheckConstraint(
        " AND ".join(f"{name} BETWEEN 0 AND 1000000000000000000" for name in _VECTOR_FIELDS),
        name="campaign_budget_reservation_vector_non_negative",
    ),
)

Table(
    "campaign_budget_events",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("ledger_id", String(64), nullable=False),
    Column("reservation_id", String(64)),
    Column("campaign_id", String(64), nullable=False),
    Column("event_type", String(100), nullable=False),
    Column("previous_state", String(32)),
    Column("next_state", String(32), nullable=False),
    Column("before_residual_sha256", String(64), nullable=False),
    Column("after_residual_sha256", String(64), nullable=False),
    Column("receipt_sha256", String(64)),
    *_owned_columns(),
    ForeignKeyConstraint(
        ("tenant_id", "campaign_id"),
        ("campaigns.tenant_id", "campaigns.id"),
        name="fk_campaign_budget_event_tenant_campaign",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "ledger_id"),
        ("campaign_budget_ledgers.tenant_id", "campaign_budget_ledgers.id"),
        name="fk_campaign_budget_event_tenant_ledger",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "reservation_id"),
        ("campaign_budget_reservations.tenant_id", "campaign_budget_reservations.id"),
        name="fk_campaign_budget_event_tenant_reservation",
    ),
)

Table(
    "plan_admission_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("campaign_id", String(64), nullable=False),
    Column("reservation_id", String(64)),
    Column("policy_decision_id", String(64)),
    Column("policy_boundary_receipt_id", String(64)),
    Column("outcome", String(32), nullable=False),
    Column("reason_code", String(100), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_sha256", String(64), nullable=False),
    Column("receipt_sha256", String(64), nullable=False),
    Column("receipt_payload", JSON, nullable=False),
    *_owned_columns(),
    ForeignKeyConstraint(
        ("tenant_id", "campaign_id"),
        ("campaigns.tenant_id", "campaigns.id"),
        name="fk_plan_admission_receipt_tenant_campaign",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "reservation_id"),
        ("campaign_budget_reservations.tenant_id", "campaign_budget_reservations.id"),
        name="fk_plan_admission_receipt_tenant_reservation",
    ),
    UniqueConstraint("tenant_id", "campaign_id", "idempotency_key", name="uq_plan_admission_receipt_idempotency"),
    UniqueConstraint("tenant_id", "request_sha256", name="uq_plan_admission_receipt_request"),
    CheckConstraint("outcome IN ('admitted','denied')", name="plan_admission_outcome_closed"),
)

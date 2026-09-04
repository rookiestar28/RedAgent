"""Relational metadata for the canonical autonomous campaign application lifecycle."""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    JSON,
    String,
    Table,
    UniqueConstraint,
)

from ._base import _owned_columns, metadata


_LIFECYCLE_VALUES = (
    "INTENT_CREATED",
    "PLAN_VALIDATED",
    "AWAITING_APPROVAL",
    "APPROVED",
    "ADMITTED",
    "EXECUTION_QUEUED",
    "RUNNING",
    "EVIDENCE_PENDING",
    "VERIFIED",
    "DENIED",
    "EXPIRED",
    "REVOKED",
    "MANUAL_REVIEW_REQUIRED",
    "RECONCILIATION_REQUIRED",
    "FAILED_CONTAINED",
    "CLEANUP_INCOMPLETE",
    "EVIDENCE_INCOMPLETE",
)
_LIFECYCLE_SQL = ",".join(f"'{value}'" for value in _LIFECYCLE_VALUES)


Table(
    "autonomous_campaign_applications",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("contract_version", String(100), nullable=False),
    Column("engagement_id", String(64), ForeignKey("engagements.id"), nullable=False),
    Column("target_id", String(64), ForeignKey("targets.id"), nullable=False),
    Column("created_by_user_id", String(64), ForeignKey("users.id"), nullable=False),
    Column("intent_sha256", String(64), nullable=False),
    Column("source_binding_sha256", String(64), nullable=False),
    Column("mode", String(32), nullable=False),
    Column("lifecycle_state", String(32), nullable=False),
    Column("aggregate_revision", BigInteger, nullable=False),
    Column("attention_reason", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "id", name="uq_autonomous_campaign_application_tenant_identity"),
    UniqueConstraint("tenant_id", "intent_sha256", name="uq_autonomous_campaign_application_tenant_intent"),
    CheckConstraint(
        "contract_version = 'redagent.autonomous-campaign-application/v1'",
        name="autonomous_campaign_application_contract_version_closed",
    ),
    CheckConstraint("mode = 'plan_only'", name="autonomous_campaign_application_mode_plan_only"),
    CheckConstraint(
        f"lifecycle_state IN ({_LIFECYCLE_SQL})",
        name="autonomous_campaign_application_lifecycle_closed",
    ),
    CheckConstraint(
        "aggregate_revision BETWEEN 1 AND 2147483647",
        name="autonomous_campaign_application_revision_bounded",
    ),
)


Table(
    "autonomous_campaign_application_events",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("application_id", String(64), nullable=False),
    Column("audit_event_id", String(64), nullable=False),
    Column("event_sequence", BigInteger, nullable=False),
    Column("event_type", String(100), nullable=False),
    Column("previous_state", String(32)),
    Column("next_state", String(32), nullable=False),
    Column("actor_user_id", String(64), nullable=False),
    Column("request_sha256", String(64), nullable=False),
    Column("lifecycle_sha256", String(64), nullable=False),
    Column("event_payload", JSON, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    ForeignKeyConstraint(
        ("tenant_id", "application_id"),
        ("autonomous_campaign_applications.tenant_id", "autonomous_campaign_applications.id"),
        name="fk_autonomous_campaign_event_tenant_application",
    ),
    ForeignKeyConstraint(
        ("audit_event_id",),
        ("audit_events.id",),
        name="fk_autonomous_campaign_event_audit",
    ),
    UniqueConstraint(
        "tenant_id",
        "application_id",
        "event_sequence",
        name="uq_autonomous_campaign_application_event_sequence",
    ),
    UniqueConstraint(
        "tenant_id",
        "audit_event_id",
        name="uq_autonomous_campaign_application_event_audit",
    ),
    CheckConstraint(
        f"previous_state IS NULL OR previous_state IN ({_LIFECYCLE_SQL})",
        name="autonomous_campaign_application_event_previous_state_closed",
    ),
    CheckConstraint(
        f"next_state IN ({_LIFECYCLE_SQL})",
        name="autonomous_campaign_application_event_next_state_closed",
    ),
    CheckConstraint(
        "event_sequence BETWEEN 1 AND 2147483647",
        name="autonomous_campaign_application_event_sequence_bounded",
    ),
)

"""SQLAlchemy table registrations for the human simulation domain."""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
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
    "human_adapter_artifacts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("adapter_id", String(100), nullable=False),
    Column("adapter_sha256", String(64), nullable=False),
    Column("owned", Boolean, nullable=False),
    Column("external_delivery_allowed", Boolean, nullable=False),
    Column("adapter_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "adapter_id", "adapter_sha256"),
)

Table(
    "human_campaign_manifests",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("campaign_id", String(100), nullable=False),
    Column("campaign_sha256", String(64), nullable=False),
    Column("purpose", String(200), nullable=False),
    Column("jurisdiction_review_id", String(100), nullable=False),
    Column("privacy_review_id", String(100), nullable=False),
    Column("roster_sha256", String(64), nullable=False),
    Column("suppression_sha256", String(64), nullable=False),
    Column("template_sha256", String(64), nullable=False),
    Column("sink_id", String(100), nullable=False),
    Column("canary_id", String(100), nullable=False),
    Column("max_deliveries", Integer, nullable=False),
    Column("rate_per_minute", Integer, nullable=False),
    Column("retention_seconds", Integer, nullable=False),
    Column("human_delivery", Boolean, nullable=False),
    Column("external_delivery", Boolean, nullable=False),
    Column("manifest_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "campaign_id", "campaign_sha256"),
)

Table(
    "human_consent_rosters",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("campaign_record_id", String(64), ForeignKey("human_campaign_manifests.id"), nullable=False),
    Column("roster_id", String(100), nullable=False),
    Column("roster_sha256", String(64), nullable=False),
    Column("recipient_count", Integer, nullable=False),
    Column("synthetic_only", Boolean, nullable=False),
    Column("consent_state", String(32), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "roster_id", "roster_sha256"),
)

Table(
    "human_suppression_lists",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("campaign_record_id", String(64), ForeignKey("human_campaign_manifests.id"), nullable=False),
    Column("suppression_id", String(100), nullable=False),
    Column("suppression_sha256", String(64), nullable=False),
    Column("deny_real_recipients", Boolean, nullable=False),
    Column("suppression_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "suppression_id", "suppression_sha256"),
)

Table(
    "human_privacy_reviews",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("campaign_record_id", String(64), ForeignKey("human_campaign_manifests.id"), nullable=False),
    Column("review_id", String(100), nullable=False),
    Column("purpose", String(200), nullable=False),
    Column("jurisdiction", String(64), nullable=False),
    Column("minimized_categories", JSON, nullable=False),
    Column("retention_seconds", Integer, nullable=False),
    Column("deletion_required", Boolean, nullable=False),
    Column("reviewed_by", String(64), nullable=False),
    Column("review_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "review_id"),
)

Table(
    "human_message_templates",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("campaign_record_id", String(64), ForeignKey("human_campaign_manifests.id"), nullable=False),
    Column("template_id", String(100), nullable=False),
    Column("template_sha256", String(64), nullable=False),
    Column("rendered_sha256", String(64), nullable=False),
    Column("external_link_count", Integer, nullable=False),
    Column("attachment_count", Integer, nullable=False),
    Column("tracking_count", Integer, nullable=False),
    Column("template_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "template_id", "template_sha256"),
)

Table(
    "human_campaign_approvals",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("approval_id", String(100), nullable=False),
    Column("campaign_record_id", String(64), ForeignKey("human_campaign_manifests.id"), nullable=False),
    Column("campaign_sha256", String(64), nullable=False),
    Column("rendered_sha256", String(64), nullable=False),
    Column("test_delivery_sha256", String(64), nullable=False),
    Column("requester_id", String(64), nullable=False),
    Column("preview_reviewer_id", String(64), nullable=False),
    Column("send_approver_id", String(64), nullable=False),
    Column("approval_state", String(32), nullable=False),
    Column("approved_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "approval_id"),
)

Table(
    "human_campaign_plans",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("plan_id", String(100), nullable=False),
    Column("campaign_record_id", String(64), ForeignKey("human_campaign_manifests.id"), nullable=False),
    Column("approval_record_id", String(64), ForeignKey("human_campaign_approvals.id"), nullable=False),
    Column("policy_decision_id", String(100), nullable=False),
    Column("roe_revision", String(100), nullable=False),
    Column("reservation_id", String(100), nullable=False),
    Column("delivery_lease_id", String(100), nullable=False),
    Column("stop_switch_id", String(100), nullable=False),
    Column("quota_id", String(100), nullable=False),
    Column("plan_sha256", String(64), nullable=False),
    Column("plan_state", String(32), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "plan_id"),
)

Table(
    "human_campaign_runs",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_id", String(100), nullable=False),
    Column("plan_record_id", String(64), ForeignKey("human_campaign_plans.id"), nullable=False),
    Column("job_id", String(100), nullable=False),
    Column("runner_id", String(100), nullable=False),
    Column("run_state", String(32), nullable=False),
    Column("new_delivery_blocked", Boolean, nullable=False),
    Column("human_delivery_count", Integer, nullable=False),
    Column("external_delivery_count", Integer, nullable=False),
    Column("deletion_verified", Boolean, nullable=False),
    Column("failure_code", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_id"),
)

Table(
    "human_delivery_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("human_campaign_runs.id"), nullable=False),
    Column("receipt_id", String(100), nullable=False),
    Column("message_id", String(100), nullable=False),
    Column("message_sha256", String(64), nullable=False),
    Column("sink_id", String(100), nullable=False),
    Column("captured", Boolean, nullable=False),
    Column("human_delivered", Boolean, nullable=False),
    Column("external_contact_count", Integer, nullable=False),
    Column("relay_count", Integer, nullable=False),
    Column("forward_count", Integer, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "receipt_id"),
)

Table(
    "human_minimized_events",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("human_campaign_runs.id"), nullable=False),
    Column("event_id", String(100), nullable=False),
    Column("message_id", String(100), nullable=False),
    Column("event_category", String(64), nullable=False),
    Column("body_sha256", String(64), nullable=False),
    Column("signature_verified", Boolean, nullable=False),
    Column("replay_checked", Boolean, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "event_id"),
)

Table(
    "human_canary_correlations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("human_campaign_runs.id"), nullable=False),
    Column("canary_id", String(100), nullable=False),
    Column("message_id", String(100), nullable=False),
    Column("sink_id", String(100), nullable=False),
    Column("correlation_sha256", String(64), nullable=False),
    Column("triggered", Boolean, nullable=False),
    Column("triggered_at", DateTime(timezone=True)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_record_id", "canary_id"),
)

Table(
    "human_stop_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("human_campaign_runs.id"), nullable=False),
    Column("receipt_id", String(100), nullable=False),
    Column("new_delivery_blocked", Boolean, nullable=False),
    Column("delivery_lease_revoked", Boolean, nullable=False),
    Column("recall_claimed", Boolean, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "receipt_id"),
)

Table(
    "human_deletion_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("human_campaign_runs.id"), nullable=False),
    Column("receipt_id", String(100), nullable=False),
    Column("deleted_message_count", Integer, nullable=False),
    Column("deleted_event_count", Integer, nullable=False),
    Column("deleted_canary_count", Integer, nullable=False),
    Column("residual_count", Integer, nullable=False),
    Column("zero_residual", Boolean, nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "receipt_id"),
)

Table(
    "human_rehearsal_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("rehearsal_id", String(100), nullable=False),
    Column("campaign_sha256", String(64), nullable=False),
    Column("plan_sha256", String(64), nullable=False),
    Column("delivery_sha256", String(64), nullable=False),
    Column("event_sha256", String(64), nullable=False),
    Column("deletion_sha256", String(64), nullable=False),
    Column("human_delivery_count", Integer, nullable=False),
    Column("external_contact_count", Integer, nullable=False),
    Column("residual_count", Integer, nullable=False),
    Column("status", String(32), nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "rehearsal_id"),
)

Table(
    "human_evidence_records",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("human_campaign_runs.id"), nullable=False),
    Column("evidence_id", String(100), nullable=False),
    Column("evidence_kind", String(64), nullable=False),
    Column("evidence_sha256", String(64), nullable=False),
    Column("redaction_state", String(32), nullable=False),
    Column("retention_expires_at", DateTime(timezone=True), nullable=False),
    Column("deleted_at", DateTime(timezone=True)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "evidence_id"),
)

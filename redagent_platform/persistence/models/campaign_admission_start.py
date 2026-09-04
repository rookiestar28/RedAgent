"""Relational metadata for the R173 autonomous admission/start bridge."""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
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


Table(
    "autonomous_campaign_execution_starts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("application_id", String(64), nullable=False),
    Column("approved_revision", BigInteger, nullable=False),
    Column("admitted_revision", BigInteger, nullable=False),
    Column("preview_id", String(64), nullable=False),
    Column("approval_receipt_id", String(64), nullable=False),
    Column("approval_receipt_sha256", String(64), nullable=False),
    Column("admission_receipt_id", String(64), nullable=False),
    Column("admission_receipt_sha256", String(64), nullable=False),
    Column("reservation_id", String(64), nullable=False),
    Column("execution_run_id", String(64), nullable=False),
    Column("workflow_id", String(100), nullable=False),
    Column("workflow_run_id", String(100)),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_sha256", String(64), nullable=False),
    Column("workflow_request_sha256", String(64), nullable=False),
    Column("workflow_input_payload", JSON, nullable=False),
    Column("input_sha256", String(64), nullable=False),
    Column("signed_authority_sha256", String(64), nullable=False),
    Column("authority_sha256", String(64), nullable=False),
    Column("domain_sha256", String(64), nullable=False),
    Column("plan_sha256", String(64), nullable=False),
    Column("certificate_sha256", String(64), nullable=False),
    Column("reserved_budget_sha256", String(64), nullable=False),
    Column("policy_revision", String(150), nullable=False),
    Column("policy_bundle_sha256", String(64), nullable=False),
    Column("lifecycle_epoch", BigInteger, nullable=False),
    Column("policy_revocation_epoch", BigInteger, nullable=False),
    Column("roe_revocation_epoch", BigInteger, nullable=False),
    Column("kill_switch_epoch", BigInteger, nullable=False),
    Column("outbox_event_id", String(64), nullable=False),
    Column("outbox_event_type", String(100), nullable=False),
    Column("application_audit_id", String(64), nullable=False),
    Column("application_event_id", String(64), nullable=False),
    Column("start_state", String(32), nullable=False),
    Column("reason_code", String(100)),
    Column("issued_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    ForeignKeyConstraint(
        ("tenant_id", "application_id"),
        ("autonomous_campaign_applications.tenant_id", "autonomous_campaign_applications.id"),
        name="fk_autonomous_campaign_start_tenant_application",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "preview_id"),
        ("autonomous_campaign_plan_previews.tenant_id", "autonomous_campaign_plan_previews.id"),
        name="fk_autonomous_campaign_start_tenant_preview",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "approval_receipt_id"),
        (
            "autonomous_campaign_plan_approval_receipts.tenant_id",
            "autonomous_campaign_plan_approval_receipts.id",
        ),
        name="fk_autonomous_campaign_start_tenant_approval",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "admission_receipt_id", "application_id"),
        (
            "plan_admission_receipts.tenant_id",
            "plan_admission_receipts.id",
            "plan_admission_receipts.campaign_id",
        ),
        name="fk_autonomous_campaign_start_tenant_admission",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "reservation_id", "application_id"),
        (
            "campaign_budget_reservations.tenant_id",
            "campaign_budget_reservations.id",
            "campaign_budget_reservations.campaign_id",
        ),
        name="fk_autonomous_campaign_start_tenant_reservation",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "execution_run_id", "application_id"),
        (
            "campaign_execution_runs.tenant_id",
            "campaign_execution_runs.id",
            "campaign_execution_runs.campaign_id",
        ),
        name="fk_autonomous_campaign_start_tenant_execution",
    ),
    ForeignKeyConstraint(
        ("application_audit_id",),
        ("audit_events.id",),
        name="fk_autonomous_campaign_start_application_audit",
    ),
    ForeignKeyConstraint(
        ("application_event_id",),
        ("autonomous_campaign_application_events.id",),
        name="fk_autonomous_campaign_start_application_event",
    ),
    UniqueConstraint("tenant_id", "id", name="uq_autonomous_campaign_start_tenant_identity"),
    UniqueConstraint(
        "tenant_id",
        "application_id",
        "approval_receipt_id",
        name="uq_autonomous_campaign_start_approval",
    ),
    UniqueConstraint(
        "tenant_id",
        "application_id",
        "idempotency_key",
        name="uq_autonomous_campaign_start_idempotency",
    ),
    UniqueConstraint(
        "tenant_id", "execution_run_id", name="uq_autonomous_campaign_start_execution"
    ),
    UniqueConstraint("tenant_id", "workflow_id", name="uq_autonomous_campaign_start_workflow"),
    UniqueConstraint("tenant_id", "outbox_event_id", name="uq_autonomous_campaign_start_outbox"),
    CheckConstraint(
        "approved_revision BETWEEN 1 AND 2147483647 AND "
        "admitted_revision = approved_revision + 1",
        name="autonomous_campaign_start_revision_bounded",
    ),
    CheckConstraint(
        "outbox_event_type = 'autonomous_campaign.start_bridge.requested.v1'",
        name="autonomous_campaign_start_event_type_closed",
    ),
    CheckConstraint(
        "start_state IN ('start_pending','execution_queued','reconciliation_required',"
        "'manual_review_required','failed_before_io')",
        name="autonomous_campaign_start_state_closed",
    ),
    CheckConstraint(
        "expires_at > issued_at",
        name="autonomous_campaign_start_expiry_ordered",
    ),
    CheckConstraint(
        "lifecycle_epoch BETWEEN 0 AND 2147483647 AND "
        "policy_revocation_epoch BETWEEN 0 AND 2147483647 AND "
        "roe_revocation_epoch BETWEEN 0 AND 2147483647 AND "
        "kill_switch_epoch BETWEEN 0 AND 2147483647",
        name="autonomous_campaign_start_epochs_bounded",
    ),
)

"""SQLAlchemy table registrations for the mcp workbench domain."""

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
    "mcp_server_registrations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("registration_id", String(100), nullable=False),
    Column("server_id", String(100), nullable=False),
    Column("protocol_version", String(32), nullable=False),
    Column("transport_kind", String(32), nullable=False),
    Column("transport_identity_sha256", String(64), nullable=False),
    Column("inventory_sha256", String(64), nullable=False),
    Column("risk_class", String(32), nullable=False),
    Column("data_class", String(32), nullable=False),
    Column("allowed_inventory_sha256", String(64), nullable=False),
    Column("registered_by", String(64), nullable=False),
    Column("reviewed_by", String(64), nullable=False),
    Column("signature_sha256", String(64), nullable=False),
    Column("registration_state", String(32), nullable=False),
    Column("issued_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "registration_id", name="uq_mcp_registration_tenant_id"),
)

Table(
    "mcp_transport_attestations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("registration_record_id", String(64), ForeignKey("mcp_server_registrations.id"), nullable=False),
    Column("attestation_id", String(100), nullable=False),
    Column("transport_kind", String(32), nullable=False),
    Column("identity_sha256", String(64), nullable=False),
    Column("authorization_profile_sha256", String(64), nullable=False),
    Column("boundary_controls_sha256", String(64), nullable=False),
    Column("transport_enabled", Boolean, nullable=False),
    Column("attestation_state", String(32), nullable=False),
    Column("attested_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "attestation_id", name="uq_mcp_transport_attestation_tenant_id"),
)

Table(
    "mcp_inventory_revisions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("registration_record_id", String(64), ForeignKey("mcp_server_registrations.id"), nullable=False),
    Column("inventory_id", String(100), nullable=False),
    Column("inventory_revision", Integer, nullable=False),
    Column("inventory_sha256", String(64), nullable=False),
    Column("protocol_version", String(32), nullable=False),
    Column("inventory_state", String(32), nullable=False),
    Column("observed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "inventory_id", "inventory_revision", name="uq_mcp_inventory_tenant_revision"),
)

Table(
    "mcp_inventory_items",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("inventory_record_id", String(64), ForeignKey("mcp_inventory_revisions.id"), nullable=False),
    Column("item_id", String(100), nullable=False),
    Column("item_name", String(128), nullable=False),
    Column("item_kind", String(32), nullable=False),
    Column("description_sha256", String(64), nullable=False),
    Column("request_schema_sha256", String(64), nullable=False),
    Column("result_schema_sha256", String(64), nullable=False),
    Column("risk_class", String(32), nullable=False),
    Column("data_class", String(32), nullable=False),
    Column("tool_mode", String(32), nullable=False),
    Column("item_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "inventory_record_id", "item_name", name="uq_mcp_inventory_item_tenant_name"),
)

Table(
    "mcp_freeze_events",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("registration_record_id", String(64), ForeignKey("mcp_server_registrations.id"), nullable=False),
    Column("freeze_id", String(100), nullable=False),
    Column("reason_code", String(100), nullable=False),
    Column("expected_inventory_sha256", String(64)),
    Column("observed_inventory_sha256", String(64)),
    Column("invalidated_approval_count", Integer, nullable=False),
    Column("freeze_state", String(32), nullable=False),
    Column("frozen_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "freeze_id", name="uq_mcp_freeze_tenant_id"),
)

Table(
    "workbench_campaign_drafts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("draft_id", String(100), nullable=False),
    Column("campaign_id", String(100), nullable=False),
    Column("draft_revision", Integer, nullable=False),
    Column("predecessor_draft_id", String(100)),
    Column("proposal_sha256", String(64), nullable=False),
    Column("authority_sha256", String(64), nullable=False),
    Column("draft_state", String(32), nullable=False),
    Column("created_by", String(64), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "draft_id", name="uq_workbench_draft_tenant_id"),
)

Table(
    "workbench_trust_items",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("draft_record_id", String(64), ForeignKey("workbench_campaign_drafts.id"), nullable=False),
    Column("item_id", String(100), nullable=False),
    Column("trust_lane", String(32), nullable=False),
    Column("summary_sha256", String(64), nullable=False),
    Column("provenance_sha256", String(64), nullable=False),
    Column("item_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "draft_record_id", "item_id", name="uq_workbench_trust_item_tenant_id"),
)

Table(
    "workbench_disclosures",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("draft_record_id", String(64), ForeignKey("workbench_campaign_drafts.id"), nullable=False),
    Column("disclosure_id", String(100), nullable=False),
    Column("sanitized_fields_sha256", String(64), nullable=False),
    Column("target_scope_sha256", String(64), nullable=False),
    Column("access_class", String(32), nullable=False),
    Column("egress_class", String(32), nullable=False),
    Column("side_effects_sha256", String(64), nullable=False),
    Column("budget_sha256", String(64), nullable=False),
    Column("disclosure_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "disclosure_id", name="uq_workbench_disclosure_tenant_id"),
)

Table(
    "workbench_reviewer_decisions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("draft_record_id", String(64), ForeignKey("workbench_campaign_drafts.id"), nullable=False),
    Column("decision_id", String(100), nullable=False),
    Column("decision_kind", String(32), nullable=False),
    Column("proposal_sha256", String(64), nullable=False),
    Column("actor_id", String(64), nullable=False),
    Column("rationale_sha256", String(64), nullable=False),
    Column("decision_state", String(32), nullable=False),
    Column("decided_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "decision_id", name="uq_workbench_decision_tenant_id"),
)

Table(
    "workbench_conclusions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("draft_record_id", String(64), ForeignKey("workbench_campaign_drafts.id"), nullable=False),
    Column("conclusion_id", String(100), nullable=False),
    Column("reviewer_id", String(64), nullable=False),
    Column("conclusion_sha256", String(64), nullable=False),
    Column("provenance_sha256", String(64), nullable=False),
    Column("conclusion_state", String(32), nullable=False),
    Column("reviewed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "conclusion_id", name="uq_workbench_conclusion_tenant_id"),
)

Table(
    "workbench_lifecycle_events",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("draft_record_id", String(64), ForeignKey("workbench_campaign_drafts.id"), nullable=False),
    Column("event_id", String(100), nullable=False),
    Column("event_kind", String(32), nullable=False),
    Column("from_state", String(32), nullable=False),
    Column("to_state", String(32), nullable=False),
    Column("event_sha256", String(64), nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "event_id", name="uq_workbench_lifecycle_tenant_id"),
)

Table(
    "mcp_qualification_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("qualification_id", String(100), nullable=False),
    Column("registration_sha256", String(64), nullable=False),
    Column("inventory_sha256", String(64), nullable=False),
    Column("scenario_sha256", String(64), nullable=False),
    Column("adversarial_case_count", Integer, nullable=False),
    Column("denied_case_count", Integer, nullable=False),
    Column("network_contact_count", Integer, nullable=False),
    Column("process_launch_count", Integer, nullable=False),
    Column("sensitive_retention_count", Integer, nullable=False),
    Column("direct_dispatch_count", Integer, nullable=False),
    Column("qualification_state", String(32), nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "qualification_id", name="uq_mcp_qualification_tenant_id"),
)

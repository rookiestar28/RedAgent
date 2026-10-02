"""Append-only canonical one-child lineage and conservatively settled peak capacity."""

from sqlalchemy import (
    CheckConstraint, Column, DateTime, ForeignKeyConstraint, Integer, JSON, String, Table, UniqueConstraint,
)

from ._base import _owned_columns, metadata


Table(
    "campaign_child_capacity_settlements",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("application_id", String(64), nullable=False),
    Column("parent_execution_run_id", String(64), nullable=False),
    Column("parent_run_version", Integer, nullable=False),
    Column("parent_reservation_id", String(64), nullable=False),
    Column("parent_admission_receipt_id", String(64), nullable=False),
    Column("source_provenance_sha256", String(64), nullable=False),
    Column("parent_effect_receipt_sha256", String(64), nullable=False),
    Column("latest_effect_completed_at", DateTime(timezone=True), nullable=False),
    Column("capacity_available_at", DateTime(timezone=True), nullable=False),
    Column("child_revision_sha256", String(64), nullable=False),
    Column("proposal_id", String(64), nullable=False),
    Column("proposal_sha256", String(64), nullable=False),
    Column("settlement_sha256", String(64), nullable=False),
    Column("settlement_payload", JSON, nullable=False),
    *_owned_columns(),
    ForeignKeyConstraint(
        ("tenant_id", "application_id"),
        ("autonomous_campaign_applications.tenant_id", "autonomous_campaign_applications.id"),
        name="fk_child_capacity_application",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "parent_execution_run_id", "application_id"),
        ("campaign_execution_runs.tenant_id", "campaign_execution_runs.id", "campaign_execution_runs.campaign_id"),
        name="fk_child_capacity_parent_run",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "parent_reservation_id", "application_id"),
        ("campaign_budget_reservations.tenant_id", "campaign_budget_reservations.id", "campaign_budget_reservations.campaign_id"),
        name="fk_child_capacity_parent_reservation",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "parent_admission_receipt_id", "application_id"),
        ("plan_admission_receipts.tenant_id", "plan_admission_receipts.id", "plan_admission_receipts.campaign_id"),
        name="fk_child_capacity_parent_admission",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "proposal_id", "application_id", "proposal_sha256"),
        ("campaign_replan_proposals.tenant_id", "campaign_replan_proposals.id", "campaign_replan_proposals.campaign_id", "campaign_replan_proposals.proposal_sha256"),
        name="fk_child_capacity_proposal",
    ),
    UniqueConstraint("tenant_id", "parent_reservation_id", name="uq_child_capacity_parent_reservation"),
    UniqueConstraint("tenant_id", "application_id", name="uq_child_capacity_application"),
    UniqueConstraint("tenant_id", "id", "application_id", "settlement_sha256", name="uq_child_capacity_identity"),
    CheckConstraint("parent_run_version BETWEEN 1 AND 2147483647", name="child_capacity_parent_version_bounded"),
    CheckConstraint("capacity_available_at >= latest_effect_completed_at + INTERVAL '60 seconds'", name="child_capacity_full_window_cooldown"),
)

Table(
    "autonomous_campaign_child_replans",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("application_id", String(64), nullable=False),
    Column("request_sha256", String(64), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("parent_execution_run_id", String(64), nullable=False),
    Column("parent_run_version", Integer, nullable=False),
    Column("parent_revision_sha256", String(64), nullable=False),
    Column("parent_admission_receipt_sha256", String(64), nullable=False),
    Column("observation_history_sha256", String(64), nullable=False),
    Column("proposal_id", String(64), nullable=False),
    Column("proposal_sha256", String(64), nullable=False),
    Column("strict_subset_proof_sha256", String(64), nullable=False),
    Column("strict_subset_proof_payload", JSON, nullable=False),
    Column("settlement_id", String(64), nullable=False),
    Column("settlement_sha256", String(64), nullable=False),
    Column("child_revision_sha256", String(64), nullable=False),
    Column("lineage_sha256", String(64), nullable=False),
    Column("lineage_payload", JSON, nullable=False),
    Column("source_payload", JSON, nullable=False),
    Column("preview_id", String(64), nullable=False),
    Column("preview_sha256", String(64), nullable=False),
    Column("replan_sequence", Integer, nullable=False),
    *_owned_columns(),
    ForeignKeyConstraint(
        ("tenant_id", "application_id"),
        ("autonomous_campaign_applications.tenant_id", "autonomous_campaign_applications.id"),
        name="fk_canonical_child_application",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "parent_execution_run_id", "application_id"),
        ("campaign_execution_runs.tenant_id", "campaign_execution_runs.id", "campaign_execution_runs.campaign_id"),
        name="fk_canonical_child_parent_run",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "proposal_id", "application_id", "proposal_sha256"),
        ("campaign_replan_proposals.tenant_id", "campaign_replan_proposals.id", "campaign_replan_proposals.campaign_id", "campaign_replan_proposals.proposal_sha256"),
        name="fk_canonical_child_proposal",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "settlement_id", "application_id", "settlement_sha256"),
        ("campaign_child_capacity_settlements.tenant_id", "campaign_child_capacity_settlements.id", "campaign_child_capacity_settlements.application_id", "campaign_child_capacity_settlements.settlement_sha256"),
        name="fk_canonical_child_settlement",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "preview_id", "application_id"),
        ("autonomous_campaign_plan_previews.tenant_id", "autonomous_campaign_plan_previews.id", "autonomous_campaign_plan_previews.application_id"),
        name="fk_canonical_child_preview",
    ),
    UniqueConstraint("tenant_id", "application_id", name="uq_canonical_child_once"),
    UniqueConstraint("tenant_id", "lineage_sha256", name="uq_canonical_child_lineage"),
    CheckConstraint("replan_sequence = 1", name="canonical_child_sequence_one"),
    CheckConstraint("parent_run_version BETWEEN 1 AND 2147483647", name="canonical_child_parent_version_bounded"),
)

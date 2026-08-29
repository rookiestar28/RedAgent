"""Append-only relational metadata for trusted observations and bounded replans."""

from __future__ import annotations

from sqlalchemy import (
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
    "campaign_observation_decisions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("campaign_id", String(64), nullable=False),
    Column("candidate_sha256", String(64), nullable=False),
    Column("decision_sha256", String(64), nullable=False),
    Column("outcome", String(32), nullable=False),
    Column("reason_code", String(100), nullable=False),
    Column("candidate_payload", JSON, nullable=False),
    Column("decision_payload", JSON, nullable=False),
    Column("decided_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    ForeignKeyConstraint(
        ("tenant_id", "campaign_id"),
        ("campaigns.tenant_id", "campaigns.id"),
        name="fk_campaign_observation_decision_tenant_campaign",
    ),
    UniqueConstraint(
        "tenant_id", "id", "campaign_id", name="uq_campaign_observation_decision_identity"
    ),
    UniqueConstraint(
        "tenant_id", "campaign_id", "candidate_sha256", name="uq_campaign_observation_candidate"
    ),
    UniqueConstraint("tenant_id", "decision_sha256", name="uq_campaign_observation_decision_digest"),
    CheckConstraint(
        "outcome IN ('trusted','producer_denied','scope_mismatch','campaign_drift',"
        "'provenance_invalid','future','stale','expired')",
        name="campaign_observation_decision_outcome_closed",
    ),
)

Table(
    "trusted_campaign_observations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("decision_id", String(64), nullable=False),
    Column("campaign_id", String(64), nullable=False),
    Column("target_id", String(150), nullable=False),
    Column("fact_id", String(150), nullable=False),
    Column("producer_kind", String(32), nullable=False),
    Column("producer_id", String(150), nullable=False),
    Column("producer_version", String(150), nullable=False),
    Column("source_record_id", String(150), nullable=False),
    Column("source_execution_run_id", String(64)),
    Column("source_node_id", String(100)),
    Column("observation_sha256", String(64), nullable=False),
    Column("provenance_sha256", String(64), nullable=False),
    Column("source_result_sha256", String(64), nullable=False),
    Column("evidence_sha256", String(64), nullable=False),
    Column("trusted_payload", JSON, nullable=False),
    Column("observed_at", DateTime(timezone=True), nullable=False),
    Column("received_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("promoted_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    ForeignKeyConstraint(
        ("tenant_id", "decision_id", "campaign_id"),
        (
            "campaign_observation_decisions.tenant_id",
            "campaign_observation_decisions.id",
            "campaign_observation_decisions.campaign_id",
        ),
        name="fk_trusted_campaign_observation_tenant_decision_campaign",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "source_execution_run_id", "source_node_id"),
        (
            "campaign_execution_nodes.tenant_id",
            "campaign_execution_nodes.execution_run_id",
            "campaign_execution_nodes.node_id",
        ),
        name="fk_trusted_observation_tenant_execution_node",
    ),
    CheckConstraint(
        "(source_execution_run_id IS NULL) = (source_node_id IS NULL)",
        name="trusted_observation_execution_source_complete",
    ),
    UniqueConstraint("tenant_id", "observation_sha256", name="uq_trusted_campaign_observation_digest"),
)

Table(
    "campaign_replan_proposals",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("campaign_id", String(64), nullable=False),
    Column("engagement_id", String(64), nullable=False),
    Column("request_sha256", String(64), nullable=False),
    Column("proposal_sha256", String(64), nullable=False),
    Column("parent_revision_id", String(150), nullable=False),
    Column("parent_revision_sha256", String(64), nullable=False),
    Column("parent_plan_sha256", String(64), nullable=False),
    Column("parent_authority_sha256", String(64), nullable=False),
    Column("parent_domain_sha256", String(64), nullable=False),
    Column("parent_admission_receipt_id", String(64), nullable=False),
    Column("parent_admission_receipt_sha256", String(64), nullable=False),
    Column("child_revision_id", String(150), nullable=False),
    Column("child_revision_sha256", String(64), nullable=False),
    Column("observation_history_sha256", String(64), nullable=False),
    Column("residual_budget_sha256", String(64), nullable=False),
    Column("planned_budget_sha256", String(64), nullable=False),
    Column("certificate_sha256", String(64), nullable=False),
    Column("subset_proof_sha256", String(64), nullable=False),
    Column("search_receipt_sha256", String(64), nullable=False),
    Column("replan_sequence", Integer, nullable=False),
    Column("lifecycle_epoch", Integer, nullable=False),
    Column("policy_revocation_epoch", Integer, nullable=False),
    Column("roe_revocation_epoch", Integer, nullable=False),
    Column("kill_switch_epoch", Integer, nullable=False),
    Column("proposal_payload", JSON, nullable=False),
    *_owned_columns(),
    ForeignKeyConstraint(
        ("tenant_id", "campaign_id"),
        ("campaigns.tenant_id", "campaigns.id"),
        name="fk_campaign_replan_proposal_tenant_campaign",
    ),
    ForeignKeyConstraint(
        (
            "tenant_id",
            "parent_admission_receipt_id",
            "campaign_id",
            "parent_admission_receipt_sha256",
        ),
        (
            "plan_admission_receipts.tenant_id",
            "plan_admission_receipts.id",
            "plan_admission_receipts.campaign_id",
            "plan_admission_receipts.receipt_sha256",
        ),
        name="fk_campaign_replan_proposal_tenant_parent_admission_campaign",
    ),
    UniqueConstraint(
        "tenant_id", "id", "campaign_id", "proposal_sha256", name="uq_campaign_replan_proposal_identity"
    ),
    UniqueConstraint("tenant_id", "request_sha256", name="uq_campaign_replan_request"),
    UniqueConstraint("tenant_id", "proposal_sha256", name="uq_campaign_replan_proposal_digest"),
    UniqueConstraint(
        "tenant_id", "campaign_id", "replan_sequence", name="uq_campaign_replan_sequence"
    ),
    UniqueConstraint("tenant_id", "child_revision_sha256", name="uq_campaign_replan_child_revision"),
    CheckConstraint(
        "replan_sequence BETWEEN 1 AND 10000",
        name="campaign_replan_sequence_bounded",
    ),
    CheckConstraint(
        "lifecycle_epoch BETWEEN 0 AND 2147483647 AND "
        "policy_revocation_epoch BETWEEN 0 AND 2147483647 AND "
        "roe_revocation_epoch BETWEEN 0 AND 2147483647 AND "
        "kill_switch_epoch BETWEEN 0 AND 2147483647",
        name="campaign_replan_epochs_bounded",
    ),
)

Table(
    "campaign_replan_acceptances",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("proposal_id", String(64), nullable=False),
    Column("proposal_sha256", String(64), nullable=False),
    Column("campaign_id", String(64), nullable=False),
    Column("admission_receipt_id", String(64), nullable=False),
    Column("admission_receipt_sha256", String(64), nullable=False),
    Column("reservation_id", String(64), nullable=False),
    Column("accepted_replan_sha256", String(64), nullable=False),
    Column("acceptance_payload", JSON, nullable=False),
    *_owned_columns(),
    ForeignKeyConstraint(
        ("tenant_id", "proposal_id", "campaign_id", "proposal_sha256"),
        (
            "campaign_replan_proposals.tenant_id",
            "campaign_replan_proposals.id",
            "campaign_replan_proposals.campaign_id",
            "campaign_replan_proposals.proposal_sha256",
        ),
        name="fk_campaign_replan_acceptance_tenant_proposal_campaign",
    ),
    ForeignKeyConstraint(
        ("tenant_id", "admission_receipt_id", "campaign_id", "admission_receipt_sha256"),
        (
            "plan_admission_receipts.tenant_id",
            "plan_admission_receipts.id",
            "plan_admission_receipts.campaign_id",
            "plan_admission_receipts.receipt_sha256",
        ),
        name="fk_campaign_replan_acceptance_tenant_admission_campaign",
    ),
    UniqueConstraint("tenant_id", "proposal_id", name="uq_campaign_replan_acceptance_proposal"),
    UniqueConstraint(
        "tenant_id", "accepted_replan_sha256", name="uq_campaign_replan_acceptance_digest"
    ),
)
